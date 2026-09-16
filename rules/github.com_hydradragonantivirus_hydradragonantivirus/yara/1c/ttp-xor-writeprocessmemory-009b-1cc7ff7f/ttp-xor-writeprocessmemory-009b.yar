rule TTP_XOR_WriteProcessMemory_009b {
  strings:
    $key_009b = { 57 e9 [2] 65 cb [2] 63 fe [2] 4d fe [2] 72 e2 }

  condition:
    any of them
}