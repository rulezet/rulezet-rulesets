rule TTP_XOR_WriteProcessMemory_f516 {
  strings:
    $key_f516 = { a2 64 [2] 90 46 [2] 96 73 [2] b8 73 [2] 87 6f }

  condition:
    any of them
}