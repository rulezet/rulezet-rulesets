rule TTP_XOR_WriteProcessMemory_f4c4 {
  strings:
    $key_f4c4 = { a3 b6 [2] 91 94 [2] 97 a1 [2] b9 a1 [2] 86 bd }

  condition:
    any of them
}