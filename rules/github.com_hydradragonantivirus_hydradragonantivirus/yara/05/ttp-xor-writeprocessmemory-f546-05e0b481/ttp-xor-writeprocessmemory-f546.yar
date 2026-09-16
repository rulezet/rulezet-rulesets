rule TTP_XOR_WriteProcessMemory_f546 {
  strings:
    $key_f546 = { a2 34 [2] 90 16 [2] 96 23 [2] b8 23 [2] 87 3f }

  condition:
    any of them
}