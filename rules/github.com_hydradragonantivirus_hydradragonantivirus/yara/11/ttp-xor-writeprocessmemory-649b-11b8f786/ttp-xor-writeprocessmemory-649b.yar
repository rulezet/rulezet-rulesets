rule TTP_XOR_WriteProcessMemory_649b {
  strings:
    $key_649b = { 33 e9 [2] 01 cb [2] 07 fe [2] 29 fe [2] 16 e2 }

  condition:
    any of them
}