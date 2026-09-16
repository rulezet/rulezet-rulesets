rule TTP_XOR_WriteProcessMemory_6e1c {
  strings:
    $key_6e1c = { 39 6e [2] 0b 4c [2] 0d 79 [2] 23 79 [2] 1c 65 }

  condition:
    any of them
}