rule TTP_XOR_WriteProcessMemory_5c7c {
  strings:
    $key_5c7c = { 0b 0e [2] 39 2c [2] 3f 19 [2] 11 19 [2] 2e 05 }

  condition:
    any of them
}