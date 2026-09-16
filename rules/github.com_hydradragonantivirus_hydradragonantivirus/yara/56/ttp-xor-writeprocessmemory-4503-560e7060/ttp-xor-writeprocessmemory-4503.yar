rule TTP_XOR_WriteProcessMemory_4503 {
  strings:
    $key_4503 = { 12 71 [2] 20 53 [2] 26 66 [2] 08 66 [2] 37 7a }

  condition:
    any of them
}