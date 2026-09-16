rule TTP_XOR_WriteProcessMemory_5c1c {
  strings:
    $key_5c1c = { 0b 6e [2] 39 4c [2] 3f 79 [2] 11 79 [2] 2e 65 }

  condition:
    any of them
}