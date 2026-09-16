rule TTP_XOR_WriteProcessMemory_43f0 {
  strings:
    $key_43f0 = { 14 82 [2] 26 a0 [2] 20 95 [2] 0e 95 [2] 31 89 }

  condition:
    any of them
}