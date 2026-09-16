rule TTP_XOR_WriteProcessMemory_366e {
  strings:
    $key_366e = { 61 1c [2] 53 3e [2] 55 0b [2] 7b 0b [2] 44 17 }

  condition:
    any of them
}