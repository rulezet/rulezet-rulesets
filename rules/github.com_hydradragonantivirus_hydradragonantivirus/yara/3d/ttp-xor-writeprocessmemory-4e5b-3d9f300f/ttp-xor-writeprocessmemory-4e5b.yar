rule TTP_XOR_WriteProcessMemory_4e5b {
  strings:
    $key_4e5b = { 19 29 [2] 2b 0b [2] 2d 3e [2] 03 3e [2] 3c 22 }

  condition:
    any of them
}