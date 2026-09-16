rule TTP_XOR_WriteProcessMemory_1703 {
  strings:
    $key_1703 = { 40 71 [2] 72 53 [2] 74 66 [2] 5a 66 [2] 65 7a }

  condition:
    any of them
}