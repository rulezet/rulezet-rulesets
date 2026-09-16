rule TTP_XOR_WriteProcessMemory_029b {
  strings:
    $key_029b = { 55 e9 [2] 67 cb [2] 61 fe [2] 4f fe [2] 70 e2 }

  condition:
    any of them
}