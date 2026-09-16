rule TTP_XOR_WriteProcessMemory_c37c {
  strings:
    $key_c37c = { 94 0e [2] a6 2c [2] a0 19 [2] 8e 19 [2] b1 05 }

  condition:
    any of them
}