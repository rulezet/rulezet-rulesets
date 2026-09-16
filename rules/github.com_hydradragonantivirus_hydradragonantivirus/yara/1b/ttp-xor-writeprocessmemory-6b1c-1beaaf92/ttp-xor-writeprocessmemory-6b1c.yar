rule TTP_XOR_WriteProcessMemory_6b1c {
  strings:
    $key_6b1c = { 3c 6e [2] 0e 4c [2] 08 79 [2] 26 79 [2] 19 65 }

  condition:
    any of them
}