rule TTP_XOR_WriteProcessMemory_7502 {
  strings:
    $key_7502 = { 22 70 [2] 10 52 [2] 16 67 [2] 38 67 [2] 07 7b }

  condition:
    any of them
}