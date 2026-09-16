rule TTP_XOR_WriteProcessMemory_43c0 {
  strings:
    $key_43c0 = { 14 b2 [2] 26 90 [2] 20 a5 [2] 0e a5 [2] 31 b9 }

  condition:
    any of them
}