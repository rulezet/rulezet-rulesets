rule TTP_XOR_WriteProcessMemory_f5c3 {
  strings:
    $key_f5c3 = { a2 b1 [2] 90 93 [2] 96 a6 [2] b8 a6 [2] 87 ba }

  condition:
    any of them
}