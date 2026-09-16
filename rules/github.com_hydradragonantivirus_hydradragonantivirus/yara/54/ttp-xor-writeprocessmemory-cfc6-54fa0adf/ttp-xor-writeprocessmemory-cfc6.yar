rule TTP_XOR_WriteProcessMemory_cfc6 {
  strings:
    $key_cfc6 = { 98 b4 [2] aa 96 [2] ac a3 [2] 82 a3 [2] bd bf }

  condition:
    any of them
}