rule TTP_XOR_WriteProcessMemory_6e1b {
  strings:
    $key_6e1b = { 39 69 [2] 0b 4b [2] 0d 7e [2] 23 7e [2] 1c 62 }

  condition:
    any of them
}