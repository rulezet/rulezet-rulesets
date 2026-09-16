rule TTP_XOR_WriteProcessMemory_480b {
  strings:
    $key_480b = { 1f 79 [2] 2d 5b [2] 2b 6e [2] 05 6e [2] 3a 72 }

  condition:
    any of them
}