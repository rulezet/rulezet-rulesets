rule TTP_XOR_WriteProcessMemory_078c {
  strings:
    $key_078c = { 50 fe [2] 62 dc [2] 64 e9 [2] 4a e9 [2] 75 f5 }

  condition:
    any of them
}