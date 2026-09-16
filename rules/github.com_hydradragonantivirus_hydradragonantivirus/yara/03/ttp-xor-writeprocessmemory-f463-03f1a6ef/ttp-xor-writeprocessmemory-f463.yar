rule TTP_XOR_WriteProcessMemory_f463 {
  strings:
    $key_f463 = { a3 11 [2] 91 33 [2] 97 06 [2] b9 06 [2] 86 1a }

  condition:
    any of them
}