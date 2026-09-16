rule TTP_XOR_WriteProcessMemory_1b21 {
  strings:
    $key_1b21 = { 4c 53 [2] 7e 71 [2] 78 44 [2] 56 44 [2] 69 58 }

  condition:
    any of them
}