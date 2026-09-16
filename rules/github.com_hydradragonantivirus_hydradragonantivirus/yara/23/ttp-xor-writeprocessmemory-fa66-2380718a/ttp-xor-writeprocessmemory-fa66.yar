rule TTP_XOR_WriteProcessMemory_fa66 {
  strings:
    $key_fa66 = { ad 14 [2] 9f 36 [2] 99 03 [2] b7 03 [2] 88 1f }

  condition:
    any of them
}