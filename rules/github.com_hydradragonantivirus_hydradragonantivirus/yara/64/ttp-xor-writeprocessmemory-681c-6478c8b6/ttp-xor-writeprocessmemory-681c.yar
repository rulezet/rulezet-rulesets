rule TTP_XOR_WriteProcessMemory_681c {
  strings:
    $key_681c = { 3f 6e [2] 0d 4c [2] 0b 79 [2] 25 79 [2] 1a 65 }

  condition:
    any of them
}