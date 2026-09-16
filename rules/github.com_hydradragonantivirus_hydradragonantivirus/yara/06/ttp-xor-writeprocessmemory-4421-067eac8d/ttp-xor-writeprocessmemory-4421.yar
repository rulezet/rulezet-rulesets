rule TTP_XOR_WriteProcessMemory_4421 {
  strings:
    $key_4421 = { 13 53 [2] 21 71 [2] 27 44 [2] 09 44 [2] 36 58 }

  condition:
    any of them
}