rule TTP_XOR_WriteProcessMemory_0a7c {
  strings:
    $key_0a7c = { 5d 0e [2] 6f 2c [2] 69 19 [2] 47 19 [2] 78 05 }

  condition:
    any of them
}