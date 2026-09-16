rule TTP_XOR_WriteProcessMemory_107c {
  strings:
    $key_107c = { 47 0e [2] 75 2c [2] 73 19 [2] 5d 19 [2] 62 05 }

  condition:
    any of them
}