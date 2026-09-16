rule TTP_XOR_WriteProcessMemory_43e5 {
  strings:
    $key_43e5 = { 14 97 [2] 26 b5 [2] 20 80 [2] 0e 80 [2] 31 9c }

  condition:
    any of them
}