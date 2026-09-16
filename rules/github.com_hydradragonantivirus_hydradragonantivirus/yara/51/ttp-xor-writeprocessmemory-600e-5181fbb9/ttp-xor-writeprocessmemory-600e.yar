rule TTP_XOR_WriteProcessMemory_600e {
  strings:
    $key_600e = { 37 7c [2] 05 5e [2] 03 6b [2] 2d 6b [2] 12 77 }

  condition:
    any of them
}