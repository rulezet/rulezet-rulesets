rule TTP_XOR_WriteProcessMemory_2521 {
  strings:
    $key_2521 = { 72 53 [2] 40 71 [2] 46 44 [2] 68 44 [2] 57 58 }

  condition:
    any of them
}