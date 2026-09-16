rule TTP_XOR_WriteProcessMemory_2703 {
  strings:
    $key_2703 = { 70 71 [2] 42 53 [2] 44 66 [2] 6a 66 [2] 55 7a }

  condition:
    any of them
}