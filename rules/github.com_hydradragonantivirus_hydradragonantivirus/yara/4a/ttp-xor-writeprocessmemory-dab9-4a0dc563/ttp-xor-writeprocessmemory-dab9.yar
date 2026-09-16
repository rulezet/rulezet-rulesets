rule TTP_XOR_WriteProcessMemory_dab9 {
  strings:
    $key_dab9 = { 8d cb [2] bf e9 [2] b9 dc [2] 97 dc [2] a8 c0 }

  condition:
    any of them
}