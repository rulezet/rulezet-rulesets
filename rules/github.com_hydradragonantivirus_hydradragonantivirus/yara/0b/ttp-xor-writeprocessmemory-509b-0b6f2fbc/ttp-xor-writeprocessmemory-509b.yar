rule TTP_XOR_WriteProcessMemory_509b {
  strings:
    $key_509b = { 07 e9 [2] 35 cb [2] 33 fe [2] 1d fe [2] 22 e2 }

  condition:
    any of them
}