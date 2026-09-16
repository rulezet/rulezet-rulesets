rule TTP_XOR_WriteProcessMemory_156c {
  strings:
    $key_156c = { 42 1e [2] 70 3c [2] 76 09 [2] 58 09 [2] 67 15 }

  condition:
    any of them
}