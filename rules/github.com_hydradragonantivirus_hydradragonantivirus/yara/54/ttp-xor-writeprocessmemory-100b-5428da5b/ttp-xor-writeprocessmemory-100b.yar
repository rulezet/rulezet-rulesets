rule TTP_XOR_WriteProcessMemory_100b {
  strings:
    $key_100b = { 47 79 [2] 75 5b [2] 73 6e [2] 5d 6e [2] 62 72 }

  condition:
    any of them
}