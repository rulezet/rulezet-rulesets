rule TTP_XOR_WriteProcessMemory_f4f4 {
  strings:
    $key_f4f4 = { a3 86 [2] 91 a4 [2] 97 91 [2] b9 91 [2] 86 8d }

  condition:
    any of them
}