rule TTP_XOR_WriteProcessMemory_0242 {
  strings:
    $key_0242 = { 55 30 [2] 67 12 [2] 61 27 [2] 4f 27 [2] 70 3b }

  condition:
    any of them
}