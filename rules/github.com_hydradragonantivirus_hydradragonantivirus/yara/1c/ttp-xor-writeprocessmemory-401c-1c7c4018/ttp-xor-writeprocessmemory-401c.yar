rule TTP_XOR_WriteProcessMemory_401c {
  strings:
    $key_401c = { 17 6e [2] 25 4c [2] 23 79 [2] 0d 79 [2] 32 65 }

  condition:
    any of them
}