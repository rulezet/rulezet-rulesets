rule TTP_XOR_WriteProcessMemory_209b {
  strings:
    $key_209b = { 77 e9 [2] 45 cb [2] 43 fe [2] 6d fe [2] 52 e2 }

  condition:
    any of them
}