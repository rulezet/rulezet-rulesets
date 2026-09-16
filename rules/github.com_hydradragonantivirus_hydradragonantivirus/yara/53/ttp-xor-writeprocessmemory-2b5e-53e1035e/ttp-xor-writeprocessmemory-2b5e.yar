rule TTP_XOR_WriteProcessMemory_2b5e {
  strings:
    $key_2b5e = { 7c 2c [2] 4e 0e [2] 48 3b [2] 66 3b [2] 59 27 }

  condition:
    any of them
}