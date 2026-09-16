rule TTP_XOR_WriteProcessMemory_2f5b {
  strings:
    $key_2f5b = { 78 29 [2] 4a 0b [2] 4c 3e [2] 62 3e [2] 5d 22 }

  condition:
    any of them
}