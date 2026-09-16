rule TTP_XOR_WriteProcessMemory_0a5b {
  strings:
    $key_0a5b = { 5d 29 [2] 6f 0b [2] 69 3e [2] 47 3e [2] 78 22 }

  condition:
    any of them
}