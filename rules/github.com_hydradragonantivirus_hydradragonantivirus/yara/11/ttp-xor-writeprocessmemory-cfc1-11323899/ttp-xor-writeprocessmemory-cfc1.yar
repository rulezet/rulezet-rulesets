rule TTP_XOR_WriteProcessMemory_cfc1 {
  strings:
    $key_cfc1 = { 98 b3 [2] aa 91 [2] ac a4 [2] 82 a4 [2] bd b8 }

  condition:
    any of them
}