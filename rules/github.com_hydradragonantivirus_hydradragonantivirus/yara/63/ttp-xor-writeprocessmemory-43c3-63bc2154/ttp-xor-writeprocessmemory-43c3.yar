rule TTP_XOR_WriteProcessMemory_43c3 {
  strings:
    $key_43c3 = { 14 b1 [2] 26 93 [2] 20 a6 [2] 0e a6 [2] 31 ba }

  condition:
    any of them
}