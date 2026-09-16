rule TTP_XOR_WriteProcessMemory_5a1c {
  strings:
    $key_5a1c = { 0d 6e [2] 3f 4c [2] 39 79 [2] 17 79 [2] 28 65 }

  condition:
    any of them
}