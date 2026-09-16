rule TTP_XOR_WriteProcessMemory_1c7c {
  strings:
    $key_1c7c = { 4b 0e [2] 79 2c [2] 7f 19 [2] 51 19 [2] 6e 05 }

  condition:
    any of them
}