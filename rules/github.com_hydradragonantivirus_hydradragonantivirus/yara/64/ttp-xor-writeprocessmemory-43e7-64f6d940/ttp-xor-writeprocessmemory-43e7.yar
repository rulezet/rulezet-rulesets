rule TTP_XOR_WriteProcessMemory_43e7 {
  strings:
    $key_43e7 = { 14 95 [2] 26 b7 [2] 20 82 [2] 0e 82 [2] 31 9e }

  condition:
    any of them
}