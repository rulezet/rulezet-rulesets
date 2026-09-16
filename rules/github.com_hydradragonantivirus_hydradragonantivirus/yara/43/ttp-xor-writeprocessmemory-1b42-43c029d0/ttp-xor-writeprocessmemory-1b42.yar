rule TTP_XOR_WriteProcessMemory_1b42 {
  strings:
    $key_1b42 = { 4c 30 [2] 7e 12 [2] 78 27 [2] 56 27 [2] 69 3b }

  condition:
    any of them
}