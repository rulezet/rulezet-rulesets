rule TTP_XOR_WriteProcessMemory_358c {
  strings:
    $key_358c = { 62 fe [2] 50 dc [2] 56 e9 [2] 78 e9 [2] 47 f5 }

  condition:
    any of them
}