rule TTP_XOR_WriteProcessMemory_0b2c {
  strings:
    $key_0b2c = { 5c 5e [2] 6e 7c [2] 68 49 [2] 46 49 [2] 79 55 }

  condition:
    any of them
}