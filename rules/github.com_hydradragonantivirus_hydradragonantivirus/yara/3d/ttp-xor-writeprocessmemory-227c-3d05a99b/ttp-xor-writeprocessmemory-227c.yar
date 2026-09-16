rule TTP_XOR_WriteProcessMemory_227c {
  strings:
    $key_227c = { 75 0e [2] 47 2c [2] 41 19 [2] 6f 19 [2] 50 05 }

  condition:
    any of them
}