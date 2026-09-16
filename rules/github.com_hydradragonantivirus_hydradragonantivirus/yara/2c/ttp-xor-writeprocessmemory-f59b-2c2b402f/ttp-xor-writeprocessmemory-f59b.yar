rule TTP_XOR_WriteProcessMemory_f59b {
  strings:
    $key_f59b = { a2 e9 [2] 90 cb [2] 96 fe [2] b8 fe [2] 87 e2 }

  condition:
    any of them
}