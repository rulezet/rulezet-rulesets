rule TTP_XOR_WriteProcessMemory_1e1c {
  strings:
    $key_1e1c = { 49 6e [2] 7b 4c [2] 7d 79 [2] 53 79 [2] 6c 65 }

  condition:
    any of them
}