rule TTP_XOR_WriteProcessMemory_5f4c {
  strings:
    $key_5f4c = { 08 3e [2] 3a 1c [2] 3c 29 [2] 12 29 [2] 2d 35 }

  condition:
    any of them
}