rule TTP_XOR_WriteProcessMemory_4c21 {
  strings:
    $key_4c21 = { 1b 53 [2] 29 71 [2] 2f 44 [2] 01 44 [2] 3e 58 }

  condition:
    any of them
}