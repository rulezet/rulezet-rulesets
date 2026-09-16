rule TTP_XOR_WriteProcessMemory_659b {
  strings:
    $key_659b = { 32 e9 [2] 00 cb [2] 06 fe [2] 28 fe [2] 17 e2 }

  condition:
    any of them
}