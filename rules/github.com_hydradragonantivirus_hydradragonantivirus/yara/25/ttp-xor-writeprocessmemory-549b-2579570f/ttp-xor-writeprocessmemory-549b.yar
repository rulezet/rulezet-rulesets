rule TTP_XOR_WriteProcessMemory_549b {
  strings:
    $key_549b = { 03 e9 [2] 31 cb [2] 37 fe [2] 19 fe [2] 26 e2 }

  condition:
    any of them
}