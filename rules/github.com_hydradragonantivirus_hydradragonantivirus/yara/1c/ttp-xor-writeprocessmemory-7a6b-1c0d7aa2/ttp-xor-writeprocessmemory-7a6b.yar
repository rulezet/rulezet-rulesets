rule TTP_XOR_WriteProcessMemory_7a6b {
  strings:
    $key_7a6b = { 2d 19 [2] 1f 3b [2] 19 0e [2] 37 0e [2] 08 12 }

  condition:
    any of them
}