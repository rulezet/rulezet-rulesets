rule TTP_XOR_WriteProcessMemory_371c {
  strings:
    $key_371c = { 60 6e [2] 52 4c [2] 54 79 [2] 7a 79 [2] 45 65 }

  condition:
    any of them
}