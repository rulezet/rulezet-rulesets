rule TTP_XOR_WriteProcessMemory_187c {
  strings:
    $key_187c = { 4f 0e [2] 7d 2c [2] 7b 19 [2] 55 19 [2] 6a 05 }

  condition:
    any of them
}