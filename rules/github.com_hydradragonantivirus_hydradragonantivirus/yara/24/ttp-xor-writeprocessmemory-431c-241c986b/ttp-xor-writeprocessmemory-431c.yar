rule TTP_XOR_WriteProcessMemory_431c {
  strings:
    $key_431c = { 14 6e [2] 26 4c [2] 20 79 [2] 0e 79 [2] 31 65 }

  condition:
    any of them
}