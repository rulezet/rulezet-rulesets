rule TTP_XOR_WriteProcessMemory_f426 {
  strings:
    $key_f426 = { a3 54 [2] 91 76 [2] 97 43 [2] b9 43 [2] 86 5f }

  condition:
    any of them
}