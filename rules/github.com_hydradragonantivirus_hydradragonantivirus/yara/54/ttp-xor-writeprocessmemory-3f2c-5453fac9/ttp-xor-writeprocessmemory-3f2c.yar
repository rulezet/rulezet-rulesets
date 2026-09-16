rule TTP_XOR_WriteProcessMemory_3f2c {
  strings:
    $key_3f2c = { 68 5e [2] 5a 7c [2] 5c 49 [2] 72 49 [2] 4d 55 }

  condition:
    any of them
}