rule TTP_XOR_WriteProcessMemory_494e {
  strings:
    $key_494e = { 1e 3c [2] 2c 1e [2] 2a 2b [2] 04 2b [2] 3b 37 }

  condition:
    any of them
}