rule TTP_XOR_WriteProcessMemory_c07c {
  strings:
    $key_c07c = { 97 0e [2] a5 2c [2] a3 19 [2] 8d 19 [2] b2 05 }

  condition:
    any of them
}