rule TTP_XOR_WriteProcessMemory_f4d6 {
  strings:
    $key_f4d6 = { a3 a4 [2] 91 86 [2] 97 b3 [2] b9 b3 [2] 86 af }

  condition:
    any of them
}