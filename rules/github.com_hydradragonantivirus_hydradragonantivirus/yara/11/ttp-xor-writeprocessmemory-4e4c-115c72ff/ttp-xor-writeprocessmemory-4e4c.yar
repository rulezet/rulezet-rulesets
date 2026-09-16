rule TTP_XOR_WriteProcessMemory_4e4c {
  strings:
    $key_4e4c = { 19 3e [2] 2b 1c [2] 2d 29 [2] 03 29 [2] 3c 35 }

  condition:
    any of them
}