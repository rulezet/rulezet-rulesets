rule TTP_XOR_WriteProcessMemory_2c5e {
  strings:
    $key_2c5e = { 7b 2c [2] 49 0e [2] 4f 3b [2] 61 3b [2] 5e 27 }

  condition:
    any of them
}