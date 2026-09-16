rule TTP_XOR_WriteProcessMemory_309b {
  strings:
    $key_309b = { 67 e9 [2] 55 cb [2] 53 fe [2] 7d fe [2] 42 e2 }

  condition:
    any of them
}