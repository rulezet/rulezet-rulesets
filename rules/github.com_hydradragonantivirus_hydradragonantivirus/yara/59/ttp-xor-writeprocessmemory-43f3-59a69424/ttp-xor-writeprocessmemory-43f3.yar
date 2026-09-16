rule TTP_XOR_WriteProcessMemory_43f3 {
  strings:
    $key_43f3 = { 14 81 [2] 26 a3 [2] 20 96 [2] 0e 96 [2] 31 8a }

  condition:
    any of them
}