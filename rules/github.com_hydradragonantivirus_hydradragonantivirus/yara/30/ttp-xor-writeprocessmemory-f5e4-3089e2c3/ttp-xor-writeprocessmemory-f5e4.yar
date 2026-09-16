rule TTP_XOR_WriteProcessMemory_f5e4 {
  strings:
    $key_f5e4 = { a2 96 [2] 90 b4 [2] 96 81 [2] b8 81 [2] 87 9d }

  condition:
    any of them
}