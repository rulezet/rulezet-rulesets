rule TTP_XOR_WriteProcessMemory_d77c {
  strings:
    $key_d77c = { 80 0e [2] b2 2c [2] b4 19 [2] 9a 19 [2] a5 05 }

  condition:
    any of them
}