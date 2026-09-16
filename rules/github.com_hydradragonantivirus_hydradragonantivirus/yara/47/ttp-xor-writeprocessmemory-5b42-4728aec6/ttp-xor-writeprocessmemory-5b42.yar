rule TTP_XOR_WriteProcessMemory_5b42 {
  strings:
    $key_5b42 = { 0c 30 [2] 3e 12 [2] 38 27 [2] 16 27 [2] 29 3b }

  condition:
    any of them
}