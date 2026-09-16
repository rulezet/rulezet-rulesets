rule TTP_XOR_WriteProcessMemory_f566 {
  strings:
    $key_f566 = { a2 14 [2] 90 36 [2] 96 03 [2] b8 03 [2] 87 1f }

  condition:
    any of them
}