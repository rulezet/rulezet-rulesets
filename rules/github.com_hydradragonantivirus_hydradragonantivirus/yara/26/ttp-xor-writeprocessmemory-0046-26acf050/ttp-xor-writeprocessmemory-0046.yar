rule TTP_XOR_WriteProcessMemory_0046 {
  strings:
    $key_0046 = { 57 34 [2] 65 16 [2] 63 23 [2] 4d 23 [2] 72 3f }

  condition:
    any of them
}