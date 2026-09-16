rule TTP_XOR_WriteProcessMemory_f467 {
  strings:
    $key_f467 = { a3 15 [2] 91 37 [2] 97 02 [2] b9 02 [2] 86 1e }

  condition:
    any of them
}