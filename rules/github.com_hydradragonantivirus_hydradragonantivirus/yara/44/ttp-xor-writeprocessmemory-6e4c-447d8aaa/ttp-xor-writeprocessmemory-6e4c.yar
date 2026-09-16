rule TTP_XOR_WriteProcessMemory_6e4c {
  strings:
    $key_6e4c = { 39 3e [2] 0b 1c [2] 0d 29 [2] 23 29 [2] 1c 35 }

  condition:
    any of them
}