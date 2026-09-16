rule TTP_XOR_WriteProcessMemory_f477 {
  strings:
    $key_f477 = { a3 05 [2] 91 27 [2] 97 12 [2] b9 12 [2] 86 0e }

  condition:
    any of them
}