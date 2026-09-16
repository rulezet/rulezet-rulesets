rule TTP_XOR_WriteProcessMemory_c67c {
  strings:
    $key_c67c = { 91 0e [2] a3 2c [2] a5 19 [2] 8b 19 [2] b4 05 }

  condition:
    any of them
}