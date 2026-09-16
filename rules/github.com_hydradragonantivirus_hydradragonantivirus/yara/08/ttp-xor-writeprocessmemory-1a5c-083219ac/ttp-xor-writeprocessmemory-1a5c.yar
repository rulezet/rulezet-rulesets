rule TTP_XOR_WriteProcessMemory_1a5c {
  strings:
    $key_1a5c = { 4d 2e [2] 7f 0c [2] 79 39 [2] 57 39 [2] 68 25 }

  condition:
    any of them
}