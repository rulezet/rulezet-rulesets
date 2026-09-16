rule TTP_XOR_WriteProcessMemory_339b {
  strings:
    $key_339b = { 64 e9 [2] 56 cb [2] 50 fe [2] 7e fe [2] 41 e2 }

  condition:
    any of them
}