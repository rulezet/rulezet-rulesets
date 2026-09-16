rule TTP_XOR_WriteProcessMemory_1b7c {
  strings:
    $key_1b7c = { 4c 0e [2] 7e 2c [2] 78 19 [2] 56 19 [2] 69 05 }

  condition:
    any of them
}