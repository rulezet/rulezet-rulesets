rule TTP_XOR_WriteProcessMemory_1b2c {
  strings:
    $key_1b2c = { 4c 5e [2] 7e 7c [2] 78 49 [2] 56 49 [2] 69 55 }

  condition:
    any of them
}