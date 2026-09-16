rule TTP_XOR_WriteProcessMemory_2b0b {
  strings:
    $key_2b0b = { 7c 79 [2] 4e 5b [2] 48 6e [2] 66 6e [2] 59 72 }

  condition:
    any of them
}