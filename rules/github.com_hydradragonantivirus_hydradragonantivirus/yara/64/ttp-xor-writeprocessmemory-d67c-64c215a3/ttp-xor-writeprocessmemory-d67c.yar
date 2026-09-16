rule TTP_XOR_WriteProcessMemory_d67c {
  strings:
    $key_d67c = { 81 0e [2] b3 2c [2] b5 19 [2] 9b 19 [2] a4 05 }

  condition:
    any of them
}