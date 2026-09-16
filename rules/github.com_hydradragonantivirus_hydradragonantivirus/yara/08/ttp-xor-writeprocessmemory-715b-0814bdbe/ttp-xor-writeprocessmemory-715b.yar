rule TTP_XOR_WriteProcessMemory_715b {
  strings:
    $key_715b = { 26 29 [2] 14 0b [2] 12 3e [2] 3c 3e [2] 03 22 }

  condition:
    any of them
}