rule TTP_XOR_WriteProcessMemory_206b {
  strings:
    $key_206b = { 77 19 [2] 45 3b [2] 43 0e [2] 6d 0e [2] 52 12 }

  condition:
    any of them
}