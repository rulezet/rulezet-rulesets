rule TTP_XOR_WriteProcessMemory_785b {
  strings:
    $key_785b = { 2f 29 [2] 1d 0b [2] 1b 3e [2] 35 3e [2] 0a 22 }

  condition:
    any of them
}