rule TTP_XOR_WriteProcessMemory_3c2c {
  strings:
    $key_3c2c = { 6b 5e [2] 59 7c [2] 5f 49 [2] 71 49 [2] 4e 55 }

  condition:
    any of them
}