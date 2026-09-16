rule TTP_XOR_WriteProcessMemory_105b {
  strings:
    $key_105b = { 47 29 [2] 75 0b [2] 73 3e [2] 5d 3e [2] 62 22 }

  condition:
    any of them
}