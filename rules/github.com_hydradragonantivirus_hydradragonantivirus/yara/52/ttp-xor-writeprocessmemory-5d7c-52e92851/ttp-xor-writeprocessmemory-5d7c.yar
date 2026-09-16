rule TTP_XOR_WriteProcessMemory_5d7c {
  strings:
    $key_5d7c = { 0a 0e [2] 38 2c [2] 3e 19 [2] 10 19 [2] 2f 05 }

  condition:
    any of them
}