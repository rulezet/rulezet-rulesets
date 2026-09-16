rule TTP_XOR_WriteProcessMemory_058c {
  strings:
    $key_058c = { 52 fe [2] 60 dc [2] 66 e9 [2] 48 e9 [2] 77 f5 }

  condition:
    any of them
}