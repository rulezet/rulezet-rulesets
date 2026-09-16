rule TTP_XOR_WriteProcessMemory_646b {
  strings:
    $key_646b = { 33 19 [2] 01 3b [2] 07 0e [2] 29 0e [2] 16 12 }

  condition:
    any of them
}