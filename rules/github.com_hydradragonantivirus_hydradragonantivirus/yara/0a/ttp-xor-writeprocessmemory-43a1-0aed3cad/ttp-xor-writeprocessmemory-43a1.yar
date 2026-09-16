rule TTP_XOR_WriteProcessMemory_43a1 {
  strings:
    $key_43a1 = { 14 d3 [2] 26 f1 [2] 20 c4 [2] 0e c4 [2] 31 d8 }

  condition:
    any of them
}