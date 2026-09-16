rule TTP_XOR_WriteProcessMemory_2e7c {
  strings:
    $key_2e7c = { 79 0e [2] 4b 2c [2] 4d 19 [2] 63 19 [2] 5c 05 }

  condition:
    any of them
}