rule TTP_XOR_WriteProcessMemory_cfc5 {
  strings:
    $key_cfc5 = { 98 b7 [2] aa 95 [2] ac a0 [2] 82 a0 [2] bd bc }

  condition:
    any of them
}