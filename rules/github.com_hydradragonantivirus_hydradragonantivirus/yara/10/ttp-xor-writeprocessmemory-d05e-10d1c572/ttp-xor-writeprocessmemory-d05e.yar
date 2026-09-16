rule TTP_XOR_WriteProcessMemory_d05e {
  strings:
    $key_d05e = { 87 2c [2] b5 0e [2] b3 3b [2] 9d 3b [2] a2 27 }

  condition:
    any of them
}