rule TTP_XOR_WriteProcessMemory_f4f0 {
  strings:
    $key_f4f0 = { a3 82 [2] 91 a0 [2] 97 95 [2] b9 95 [2] 86 89 }

  condition:
    any of them
}