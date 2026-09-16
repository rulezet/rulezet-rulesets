rule TTP_XOR_WriteProcessMemory_e95e {
  strings:
    $key_e95e = { be 2c [2] 8c 0e [2] 8a 3b [2] a4 3b [2] 9b 27 }

  condition:
    any of them
}