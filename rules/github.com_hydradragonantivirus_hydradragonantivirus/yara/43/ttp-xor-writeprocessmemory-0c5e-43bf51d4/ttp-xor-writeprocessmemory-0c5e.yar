rule TTP_XOR_WriteProcessMemory_0c5e {
  strings:
    $key_0c5e = { 5b 2c [2] 69 0e [2] 6f 3b [2] 41 3b [2] 7e 27 }

  condition:
    any of them
}