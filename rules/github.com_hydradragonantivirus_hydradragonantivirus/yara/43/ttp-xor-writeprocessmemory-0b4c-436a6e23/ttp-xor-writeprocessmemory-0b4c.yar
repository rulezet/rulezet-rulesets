rule TTP_XOR_WriteProcessMemory_0b4c {
  strings:
    $key_0b4c = { 5c 3e [2] 6e 1c [2] 68 29 [2] 46 29 [2] 79 35 }

  condition:
    any of them
}