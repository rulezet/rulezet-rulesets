rule TTP_XOR_WriteProcessMemory_6b2c {
  strings:
    $key_6b2c = { 3c 5e [2] 0e 7c [2] 08 49 [2] 26 49 [2] 19 55 }

  condition:
    any of them
}