rule TTP_XOR_WriteProcessMemory_f247 {
  strings:
    $key_f247 = { a5 35 [2] 97 17 [2] 91 22 [2] bf 22 [2] 80 3e }

  condition:
    any of them
}