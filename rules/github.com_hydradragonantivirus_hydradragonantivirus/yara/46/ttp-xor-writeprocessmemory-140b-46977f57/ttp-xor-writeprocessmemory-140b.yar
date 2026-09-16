rule TTP_XOR_WriteProcessMemory_140b {
  strings:
    $key_140b = { 43 79 [2] 71 5b [2] 77 6e [2] 59 6e [2] 66 72 }

  condition:
    any of them
}