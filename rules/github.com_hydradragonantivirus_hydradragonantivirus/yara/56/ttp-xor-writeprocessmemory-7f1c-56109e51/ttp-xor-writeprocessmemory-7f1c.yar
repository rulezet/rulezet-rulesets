rule TTP_XOR_WriteProcessMemory_7f1c {
  strings:
    $key_7f1c = { 28 6e [2] 1a 4c [2] 1c 79 [2] 32 79 [2] 0d 65 }

  condition:
    any of them
}