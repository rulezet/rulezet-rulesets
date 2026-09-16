rule TTP_XOR_WriteProcessMemory_f4c2 {
  strings:
    $key_f4c2 = { a3 b0 [2] 91 92 [2] 97 a7 [2] b9 a7 [2] 86 bb }

  condition:
    any of them
}