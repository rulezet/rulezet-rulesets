rule TTP_XOR_WriteProcessMemory_0e7c {
  strings:
    $key_0e7c = { 59 0e [2] 6b 2c [2] 6d 19 [2] 43 19 [2] 7c 05 }

  condition:
    any of them
}