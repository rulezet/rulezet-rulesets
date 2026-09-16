rule TTP_XOR_WriteProcessMemory_3e5e {
  strings:
    $key_3e5e = { 69 2c [2] 5b 0e [2] 5d 3b [2] 73 3b [2] 4c 27 }

  condition:
    any of them
}