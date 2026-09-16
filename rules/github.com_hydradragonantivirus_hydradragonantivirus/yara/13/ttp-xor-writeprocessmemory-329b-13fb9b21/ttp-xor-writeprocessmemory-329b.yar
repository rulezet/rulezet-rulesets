rule TTP_XOR_WriteProcessMemory_329b {
  strings:
    $key_329b = { 65 e9 [2] 57 cb [2] 51 fe [2] 7f fe [2] 40 e2 }

  condition:
    any of them
}