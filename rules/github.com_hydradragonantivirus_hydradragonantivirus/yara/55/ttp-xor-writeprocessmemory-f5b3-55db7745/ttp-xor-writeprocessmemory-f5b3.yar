rule TTP_XOR_WriteProcessMemory_f5b3 {
  strings:
    $key_f5b3 = { a2 c1 [2] 90 e3 [2] 96 d6 [2] b8 d6 [2] 87 ca }

  condition:
    any of them
}