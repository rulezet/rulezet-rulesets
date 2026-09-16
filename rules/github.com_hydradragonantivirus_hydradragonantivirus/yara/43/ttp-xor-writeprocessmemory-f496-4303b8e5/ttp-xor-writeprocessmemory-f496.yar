rule TTP_XOR_WriteProcessMemory_f496 {
  strings:
    $key_f496 = { a3 e4 [2] 91 c6 [2] 97 f3 [2] b9 f3 [2] 86 ef }

  condition:
    any of them
}