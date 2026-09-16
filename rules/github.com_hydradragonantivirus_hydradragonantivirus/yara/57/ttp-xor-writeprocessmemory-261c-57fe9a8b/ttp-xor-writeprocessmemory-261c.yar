rule TTP_XOR_WriteProcessMemory_261c {
  strings:
    $key_261c = { 71 6e [2] 43 4c [2] 45 79 [2] 6b 79 [2] 54 65 }

  condition:
    any of them
}