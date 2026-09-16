rule TTP_XOR_WriteProcessMemory_4703 {
  strings:
    $key_4703 = { 10 71 [2] 22 53 [2] 24 66 [2] 0a 66 [2] 35 7a }

  condition:
    any of them
}