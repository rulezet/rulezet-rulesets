rule TTP_XOR_WriteProcessMemory_6e2b {
  strings:
    $key_6e2b = { 39 59 [2] 0b 7b [2] 0d 4e [2] 23 4e [2] 1c 52 }

  condition:
    any of them
}