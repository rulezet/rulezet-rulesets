rule TTP_XOR_WriteProcessMemory_791c {
  strings:
    $key_791c = { 2e 6e [2] 1c 4c [2] 1a 79 [2] 34 79 [2] 0b 65 }

  condition:
    any of them
}