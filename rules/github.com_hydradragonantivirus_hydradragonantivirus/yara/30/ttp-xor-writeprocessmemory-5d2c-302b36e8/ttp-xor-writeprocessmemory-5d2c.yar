rule TTP_XOR_WriteProcessMemory_5d2c {
  strings:
    $key_5d2c = { 0a 5e [2] 38 7c [2] 3e 49 [2] 10 49 [2] 2f 55 }

  condition:
    any of them
}