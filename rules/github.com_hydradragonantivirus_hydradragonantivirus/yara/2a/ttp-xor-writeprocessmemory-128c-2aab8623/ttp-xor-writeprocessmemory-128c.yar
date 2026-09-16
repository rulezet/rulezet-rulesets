rule TTP_XOR_WriteProcessMemory_128c {
  strings:
    $key_128c = { 45 fe [2] 77 dc [2] 71 e9 [2] 5f e9 [2] 60 f5 }

  condition:
    any of them
}