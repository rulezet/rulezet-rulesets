rule TTP_XOR_WriteProcessMemory_438c {
  strings:
    $key_438c = { 14 fe [2] 26 dc [2] 20 e9 [2] 0e e9 [2] 31 f5 }

  condition:
    any of them
}