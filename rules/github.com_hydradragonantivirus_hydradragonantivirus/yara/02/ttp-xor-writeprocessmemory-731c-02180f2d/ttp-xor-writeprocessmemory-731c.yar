rule TTP_XOR_WriteProcessMemory_731c {
  strings:
    $key_731c = { 24 6e [2] 16 4c [2] 10 79 [2] 3e 79 [2] 01 65 }

  condition:
    any of them
}