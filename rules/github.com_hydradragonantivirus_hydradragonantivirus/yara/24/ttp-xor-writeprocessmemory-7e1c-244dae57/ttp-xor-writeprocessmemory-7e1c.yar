rule TTP_XOR_WriteProcessMemory_7e1c {
  strings:
    $key_7e1c = { 29 6e [2] 1b 4c [2] 1d 79 [2] 33 79 [2] 0c 65 }

  condition:
    any of them
}