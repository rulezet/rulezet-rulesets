rule TTP_XOR_WriteProcessMemory_43d7 {
  strings:
    $key_43d7 = { 14 a5 [2] 26 87 [2] 20 b2 [2] 0e b2 [2] 31 ae }

  condition:
    any of them
}