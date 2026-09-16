rule TTP_XOR_WriteProcessMemory_205b {
  strings:
    $key_205b = { 77 29 [2] 45 0b [2] 43 3e [2] 6d 3e [2] 52 22 }

  condition:
    any of them
}