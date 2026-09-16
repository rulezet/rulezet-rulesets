rule TTP_XOR_WriteProcessMemory_5503 {
  strings:
    $key_5503 = { 02 71 [2] 30 53 [2] 36 66 [2] 18 66 [2] 27 7a }

  condition:
    any of them
}