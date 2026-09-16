rule TTP_XOR_WriteProcessMemory_0442 {
  strings:
    $key_0442 = { 53 30 [2] 61 12 [2] 67 27 [2] 49 27 [2] 76 3b }

  condition:
    any of them
}