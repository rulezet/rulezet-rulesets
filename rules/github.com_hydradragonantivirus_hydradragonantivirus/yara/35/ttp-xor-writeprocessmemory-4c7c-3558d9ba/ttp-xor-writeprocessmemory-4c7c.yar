rule TTP_XOR_WriteProcessMemory_4c7c {
  strings:
    $key_4c7c = { 1b 0e [2] 29 2c [2] 2f 19 [2] 01 19 [2] 3e 05 }

  condition:
    any of them
}