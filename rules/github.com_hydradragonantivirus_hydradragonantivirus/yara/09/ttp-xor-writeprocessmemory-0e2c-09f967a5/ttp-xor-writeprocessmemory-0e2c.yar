rule TTP_XOR_WriteProcessMemory_0e2c {
  strings:
    $key_0e2c = { 59 5e [2] 6b 7c [2] 6d 49 [2] 43 49 [2] 7c 55 }

  condition:
    any of them
}