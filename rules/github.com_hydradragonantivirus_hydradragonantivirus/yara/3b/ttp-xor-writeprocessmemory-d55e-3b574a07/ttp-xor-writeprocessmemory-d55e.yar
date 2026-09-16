rule TTP_XOR_WriteProcessMemory_d55e {
  strings:
    $key_d55e = { 82 2c [2] b0 0e [2] b6 3b [2] 98 3b [2] a7 27 }

  condition:
    any of them
}