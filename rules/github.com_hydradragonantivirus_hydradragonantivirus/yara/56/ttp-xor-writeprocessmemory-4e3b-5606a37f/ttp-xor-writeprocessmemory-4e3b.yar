rule TTP_XOR_WriteProcessMemory_4e3b {
  strings:
    $key_4e3b = { 19 49 [2] 2b 6b [2] 2d 5e [2] 03 5e [2] 3c 42 }

  condition:
    any of them
}