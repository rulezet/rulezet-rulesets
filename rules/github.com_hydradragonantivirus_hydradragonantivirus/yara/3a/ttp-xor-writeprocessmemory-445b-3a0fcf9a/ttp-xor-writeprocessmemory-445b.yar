rule TTP_XOR_WriteProcessMemory_445b {
  strings:
    $key_445b = { 13 29 [2] 21 0b [2] 27 3e [2] 09 3e [2] 36 22 }

  condition:
    any of them
}