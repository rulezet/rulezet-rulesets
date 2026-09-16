rule TTP_XOR_WriteProcessMemory_43f2 {
  strings:
    $key_43f2 = { 14 80 [2] 26 a2 [2] 20 97 [2] 0e 97 [2] 31 8b }

  condition:
    any of them
}