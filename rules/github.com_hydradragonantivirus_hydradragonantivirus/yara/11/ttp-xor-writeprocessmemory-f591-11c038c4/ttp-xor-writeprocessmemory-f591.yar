rule TTP_XOR_WriteProcessMemory_f591 {
  strings:
    $key_f591 = { a2 e3 [2] 90 c1 [2] 96 f4 [2] b8 f4 [2] 87 e8 }

  condition:
    any of them
}