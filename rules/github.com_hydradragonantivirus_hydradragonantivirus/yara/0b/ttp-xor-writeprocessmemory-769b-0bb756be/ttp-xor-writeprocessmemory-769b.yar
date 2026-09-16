rule TTP_XOR_WriteProcessMemory_769b {
  strings:
    $key_769b = { 21 e9 [2] 13 cb [2] 15 fe [2] 3b fe [2] 04 e2 }

  condition:
    any of them
}