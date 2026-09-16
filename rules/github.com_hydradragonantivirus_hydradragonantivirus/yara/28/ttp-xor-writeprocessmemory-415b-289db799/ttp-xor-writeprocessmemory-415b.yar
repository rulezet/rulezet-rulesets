rule TTP_XOR_WriteProcessMemory_415b {
  strings:
    $key_415b = { 16 29 [2] 24 0b [2] 22 3e [2] 0c 3e [2] 33 22 }

  condition:
    any of them
}