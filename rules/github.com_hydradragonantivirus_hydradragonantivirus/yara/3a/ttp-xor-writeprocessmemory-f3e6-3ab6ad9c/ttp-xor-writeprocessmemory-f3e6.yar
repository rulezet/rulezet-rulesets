rule TTP_XOR_WriteProcessMemory_f3e6 {
  strings:
    $key_f3e6 = { a4 94 [2] 96 b6 [2] 90 83 [2] be 83 [2] 81 9f }

  condition:
    any of them
}