rule TTP_XOR_WriteProcessMemory_2e5e {
  strings:
    $key_2e5e = { 79 2c [2] 4b 0e [2] 4d 3b [2] 63 3b [2] 5c 27 }

  condition:
    any of them
}