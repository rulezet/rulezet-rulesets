rule TTP_XOR_WriteProcessMemory_2d7c {
  strings:
    $key_2d7c = { 7a 0e [2] 48 2c [2] 4e 19 [2] 60 19 [2] 5f 05 }

  condition:
    any of them
}