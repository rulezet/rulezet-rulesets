rule TTP_XOR_WriteProcessMemory_d455 {
  strings:
    $key_d455 = { 83 27 [2] b1 05 [2] b7 30 [2] 99 30 [2] a6 2c }

  condition:
    any of them
}