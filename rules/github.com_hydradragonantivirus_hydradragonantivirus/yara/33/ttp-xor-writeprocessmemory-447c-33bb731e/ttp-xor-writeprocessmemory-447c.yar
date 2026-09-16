rule TTP_XOR_WriteProcessMemory_447c {
  strings:
    $key_447c = { 13 0e [2] 21 2c [2] 27 19 [2] 09 19 [2] 36 05 }

  condition:
    any of them
}