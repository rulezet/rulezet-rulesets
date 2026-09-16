rule TTP_XOR_WriteProcessMemory_6f7c {
  strings:
    $key_6f7c = { 38 0e [2] 0a 2c [2] 0c 19 [2] 22 19 [2] 1d 05 }

  condition:
    any of them
}