rule TTP_XOR_WriteProcessMemory_1a4c {
  strings:
    $key_1a4c = { 4d 3e [2] 7f 1c [2] 79 29 [2] 57 29 [2] 68 35 }

  condition:
    any of them
}