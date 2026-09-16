rule TTP_XOR_WriteProcessMemory_7c42 {
  strings:
    $key_7c42 = { 2b 30 [2] 19 12 [2] 1f 27 [2] 31 27 [2] 0e 3b }

  condition:
    any of them
}