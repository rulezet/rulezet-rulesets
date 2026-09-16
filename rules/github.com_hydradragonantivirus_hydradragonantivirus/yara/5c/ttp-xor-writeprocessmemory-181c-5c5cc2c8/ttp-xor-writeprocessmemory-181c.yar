rule TTP_XOR_WriteProcessMemory_181c {
  strings:
    $key_181c = { 4f 6e [2] 7d 4c [2] 7b 79 [2] 55 79 [2] 6a 65 }

  condition:
    any of them
}