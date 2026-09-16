rule TTP_XOR_WriteProcessMemory_c9f9 {
  strings:
    $key_c9f9 = { 9e 8b [2] ac a9 [2] aa 9c [2] 84 9c [2] bb 80 }

  condition:
    any of them
}