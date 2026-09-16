rule TTP_XOR_WriteProcessMemory_741c {
  strings:
    $key_741c = { 23 6e [2] 11 4c [2] 17 79 [2] 39 79 [2] 06 65 }

  condition:
    any of them
}