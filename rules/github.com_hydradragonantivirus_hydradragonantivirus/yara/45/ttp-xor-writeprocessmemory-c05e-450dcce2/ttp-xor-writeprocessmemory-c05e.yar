rule TTP_XOR_WriteProcessMemory_c05e {
  strings:
    $key_c05e = { 97 2c [2] a5 0e [2] a3 3b [2] 8d 3b [2] b2 27 }

  condition:
    any of them
}