rule TTP_XOR_WriteProcessMemory_3c7c {
  strings:
    $key_3c7c = { 6b 0e [2] 59 2c [2] 5f 19 [2] 71 19 [2] 4e 05 }

  condition:
    any of them
}