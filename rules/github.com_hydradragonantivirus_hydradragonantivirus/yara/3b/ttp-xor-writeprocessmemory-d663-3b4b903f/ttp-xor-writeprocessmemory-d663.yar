rule TTP_XOR_WriteProcessMemory_d663 {
  strings:
    $key_d663 = { 81 11 [2] b3 33 [2] b5 06 [2] 9b 06 [2] a4 1a }

  condition:
    any of them
}