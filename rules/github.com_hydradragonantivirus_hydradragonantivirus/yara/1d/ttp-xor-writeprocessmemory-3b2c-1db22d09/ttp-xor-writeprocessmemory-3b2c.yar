rule TTP_XOR_WriteProcessMemory_3b2c {
  strings:
    $key_3b2c = { 6c 5e [2] 5e 7c [2] 58 49 [2] 76 49 [2] 49 55 }

  condition:
    any of them
}