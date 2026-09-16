rule TTP_XOR_WriteProcessMemory_1b5e {
  strings:
    $key_1b5e = { 4c 2c [2] 7e 0e [2] 78 3b [2] 56 3b [2] 69 27 }

  condition:
    any of them
}