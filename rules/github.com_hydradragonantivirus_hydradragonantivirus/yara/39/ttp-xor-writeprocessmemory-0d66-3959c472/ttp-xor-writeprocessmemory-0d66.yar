rule TTP_XOR_WriteProcessMemory_0d66 {
  strings:
    $key_0d66 = { 5a 14 [2] 68 36 [2] 6e 03 [2] 40 03 [2] 7f 1f }

  condition:
    any of them
}