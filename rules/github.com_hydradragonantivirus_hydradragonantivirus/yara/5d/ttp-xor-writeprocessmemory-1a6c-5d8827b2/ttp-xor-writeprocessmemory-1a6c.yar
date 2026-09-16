rule TTP_XOR_WriteProcessMemory_1a6c {
  strings:
    $key_1a6c = { 4d 1e [2] 7f 3c [2] 79 09 [2] 57 09 [2] 68 15 }

  condition:
    any of them
}