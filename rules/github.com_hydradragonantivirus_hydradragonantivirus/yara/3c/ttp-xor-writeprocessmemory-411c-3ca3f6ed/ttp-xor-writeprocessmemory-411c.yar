rule TTP_XOR_WriteProcessMemory_411c {
  strings:
    $key_411c = { 16 6e [2] 24 4c [2] 22 79 [2] 0c 79 [2] 33 65 }

  condition:
    any of them
}