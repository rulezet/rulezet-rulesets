rule TTP_XOR_WriteProcessMemory_5a7c {
  strings:
    $key_5a7c = { 0d 0e [2] 3f 2c [2] 39 19 [2] 17 19 [2] 28 05 }

  condition:
    any of them
}