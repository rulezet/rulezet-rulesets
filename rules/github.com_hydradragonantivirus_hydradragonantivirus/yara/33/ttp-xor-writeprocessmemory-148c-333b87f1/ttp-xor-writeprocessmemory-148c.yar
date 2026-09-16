rule TTP_XOR_WriteProcessMemory_148c {
  strings:
    $key_148c = { 43 fe [2] 71 dc [2] 77 e9 [2] 59 e9 [2] 66 f5 }

  condition:
    any of them
}