rule TTP_XOR_WriteProcessMemory_f576 {
  strings:
    $key_f576 = { a2 04 [2] 90 26 [2] 96 13 [2] b8 13 [2] 87 0f }

  condition:
    any of them
}