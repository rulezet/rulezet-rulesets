rule TTP_XOR_WriteProcessMemory_d17c {
  strings:
    $key_d17c = { 86 0e [2] b4 2c [2] b2 19 [2] 9c 19 [2] a3 05 }

  condition:
    any of them
}