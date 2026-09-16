rule TTP_XOR_WriteProcessMemory_d650 {
  strings:
    $key_d650 = { 81 22 [2] b3 00 [2] b5 35 [2] 9b 35 [2] a4 29 }

  condition:
    any of them
}