rule TTP_XOR_WriteProcessMemory_486b {
  strings:
    $key_486b = { 1f 19 [2] 2d 3b [2] 2b 0e [2] 05 0e [2] 3a 12 }

  condition:
    any of them
}