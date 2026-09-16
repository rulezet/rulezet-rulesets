rule TTP_XOR_WriteProcessMemory_035e {
  strings:
    $key_035e = { 54 2c [2] 66 0e [2] 60 3b [2] 4e 3b [2] 71 27 }

  condition:
    any of them
}