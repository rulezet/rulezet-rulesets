rule TTP_XOR_WriteProcessMemory_149b {
  strings:
    $key_149b = { 43 e9 [2] 71 cb [2] 77 fe [2] 59 fe [2] 66 e2 }

  condition:
    any of them
}