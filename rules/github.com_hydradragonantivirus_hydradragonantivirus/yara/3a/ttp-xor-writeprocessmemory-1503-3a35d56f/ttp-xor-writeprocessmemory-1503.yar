rule TTP_XOR_WriteProcessMemory_1503 {
  strings:
    $key_1503 = { 42 71 [2] 70 53 [2] 76 66 [2] 58 66 [2] 67 7a }

  condition:
    any of them
}