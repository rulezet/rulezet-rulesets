rule TTP_XOR_WriteProcessMemory_5c2c {
  strings:
    $key_5c2c = { 0b 5e [2] 39 7c [2] 3f 49 [2] 11 49 [2] 2e 55 }

  condition:
    any of them
}