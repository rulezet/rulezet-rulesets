rule TTP_XOR_WriteProcessMemory_f4c6 {
  strings:
    $key_f4c6 = { a3 b4 [2] 91 96 [2] 97 a3 [2] b9 a3 [2] 86 bf }

  condition:
    any of them
}