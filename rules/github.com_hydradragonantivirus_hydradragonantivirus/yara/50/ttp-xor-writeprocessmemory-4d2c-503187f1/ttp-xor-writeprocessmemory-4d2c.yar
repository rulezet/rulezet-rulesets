rule TTP_XOR_WriteProcessMemory_4d2c {
  strings:
    $key_4d2c = { 1a 5e [2] 28 7c [2] 2e 49 [2] 00 49 [2] 3f 55 }

  condition:
    any of them
}