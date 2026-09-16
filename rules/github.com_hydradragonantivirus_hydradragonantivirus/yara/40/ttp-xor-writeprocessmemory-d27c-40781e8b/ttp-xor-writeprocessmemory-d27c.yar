rule TTP_XOR_WriteProcessMemory_d27c {
  strings:
    $key_d27c = { 85 0e [2] b7 2c [2] b1 19 [2] 9f 19 [2] a0 05 }

  condition:
    any of them
}