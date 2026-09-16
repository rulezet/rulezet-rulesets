rule TTP_XOR_WriteProcessMemory_129b {
  strings:
    $key_129b = { 45 e9 [2] 77 cb [2] 71 fe [2] 5f fe [2] 60 e2 }

  condition:
    any of them
}