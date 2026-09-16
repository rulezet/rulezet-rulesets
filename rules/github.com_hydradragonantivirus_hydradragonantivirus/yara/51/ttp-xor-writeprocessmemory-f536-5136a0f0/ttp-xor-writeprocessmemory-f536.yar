rule TTP_XOR_WriteProcessMemory_f536 {
  strings:
    $key_f536 = { a2 44 [2] 90 66 [2] 96 53 [2] b8 53 [2] 87 4f }

  condition:
    any of them
}