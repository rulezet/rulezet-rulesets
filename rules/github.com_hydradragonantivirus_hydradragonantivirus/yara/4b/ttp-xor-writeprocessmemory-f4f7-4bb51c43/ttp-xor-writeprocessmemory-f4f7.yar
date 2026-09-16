rule TTP_XOR_WriteProcessMemory_f4f7 {
  strings:
    $key_f4f7 = { a3 85 [2] 91 a7 [2] 97 92 [2] b9 92 [2] 86 8e }

  condition:
    any of them
}