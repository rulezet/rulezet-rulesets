rule TTP_XOR_WriteProcessMemory_d670 {
  strings:
    $key_d670 = { 81 02 [2] b3 20 [2] b5 15 [2] 9b 15 [2] a4 09 }

  condition:
    any of them
}