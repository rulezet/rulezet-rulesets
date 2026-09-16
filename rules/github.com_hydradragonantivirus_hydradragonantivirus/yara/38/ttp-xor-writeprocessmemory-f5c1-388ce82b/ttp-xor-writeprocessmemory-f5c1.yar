rule TTP_XOR_WriteProcessMemory_f5c1 {
  strings:
    $key_f5c1 = { a2 b3 [2] 90 91 [2] 96 a4 [2] b8 a4 [2] 87 b8 }

  condition:
    any of them
}