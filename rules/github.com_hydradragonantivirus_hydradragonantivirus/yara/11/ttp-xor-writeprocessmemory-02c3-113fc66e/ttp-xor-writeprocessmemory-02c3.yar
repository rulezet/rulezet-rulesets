rule TTP_XOR_WriteProcessMemory_02c3 {
  strings:
    $key_02c3 = { 55 b1 [2] 67 93 [2] 61 a6 [2] 4f a6 [2] 70 ba }

  condition:
    any of them
}