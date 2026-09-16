rule TTP_XOR_WriteProcessMemory_3e2c {
  strings:
    $key_3e2c = { 69 5e [2] 5b 7c [2] 5d 49 [2] 73 49 [2] 4c 55 }

  condition:
    any of them
}