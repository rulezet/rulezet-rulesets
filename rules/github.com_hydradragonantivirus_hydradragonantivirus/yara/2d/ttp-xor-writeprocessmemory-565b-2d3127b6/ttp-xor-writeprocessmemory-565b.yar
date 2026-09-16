rule TTP_XOR_WriteProcessMemory_565b {
  strings:
    $key_565b = { 01 29 [2] 33 0b [2] 35 3e [2] 1b 3e [2] 24 22 }

  condition:
    any of them
}