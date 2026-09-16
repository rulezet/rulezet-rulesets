rule TTP_XOR_WriteProcessMemory_1021 {
  strings:
    $key_1021 = { 47 53 [2] 75 71 [2] 73 44 [2] 5d 44 [2] 62 58 }

  condition:
    any of them
}