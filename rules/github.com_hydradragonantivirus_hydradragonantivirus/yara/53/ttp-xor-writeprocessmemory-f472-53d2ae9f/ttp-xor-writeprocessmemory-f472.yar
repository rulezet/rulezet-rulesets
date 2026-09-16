rule TTP_XOR_WriteProcessMemory_f472 {
  strings:
    $key_f472 = { a3 00 [2] 91 22 [2] 97 17 [2] b9 17 [2] 86 0b }

  condition:
    any of them
}