rule TTP_XOR_WriteProcessMemory_f4e1 {
  strings:
    $key_f4e1 = { a3 93 [2] 91 b1 [2] 97 84 [2] b9 84 [2] 86 98 }

  condition:
    any of them
}