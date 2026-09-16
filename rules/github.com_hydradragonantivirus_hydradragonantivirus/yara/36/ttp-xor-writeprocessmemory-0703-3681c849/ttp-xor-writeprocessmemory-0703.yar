rule TTP_XOR_WriteProcessMemory_0703 {
  strings:
    $key_0703 = { 50 71 [2] 62 53 [2] 64 66 [2] 4a 66 [2] 75 7a }

  condition:
    any of them
}