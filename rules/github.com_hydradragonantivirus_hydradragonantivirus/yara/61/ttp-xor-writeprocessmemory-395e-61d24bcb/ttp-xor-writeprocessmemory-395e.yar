rule TTP_XOR_WriteProcessMemory_395e {
  strings:
    $key_395e = { 6e 2c [2] 5c 0e [2] 5a 3b [2] 74 3b [2] 4b 27 }

  condition:
    any of them
}