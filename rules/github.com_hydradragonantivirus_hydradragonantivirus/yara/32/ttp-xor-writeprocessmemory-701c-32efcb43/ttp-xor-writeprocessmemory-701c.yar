rule TTP_XOR_WriteProcessMemory_701c {
  strings:
    $key_701c = { 27 6e [2] 15 4c [2] 13 79 [2] 3d 79 [2] 02 65 }

  condition:
    any of them
}