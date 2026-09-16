rule TTP_XOR_WriteProcessMemory_3f7c {
  strings:
    $key_3f7c = { 68 0e [2] 5a 2c [2] 5c 19 [2] 72 19 [2] 4d 05 }

  condition:
    any of them
}