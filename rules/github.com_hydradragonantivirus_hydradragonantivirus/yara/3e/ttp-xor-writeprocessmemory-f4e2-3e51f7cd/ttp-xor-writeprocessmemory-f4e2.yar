rule TTP_XOR_WriteProcessMemory_f4e2 {
  strings:
    $key_f4e2 = { a3 90 [2] 91 b2 [2] 97 87 [2] b9 87 [2] 86 9b }

  condition:
    any of them
}