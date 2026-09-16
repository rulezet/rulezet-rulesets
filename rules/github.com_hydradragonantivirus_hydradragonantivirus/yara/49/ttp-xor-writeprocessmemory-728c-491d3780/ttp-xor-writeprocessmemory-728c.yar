rule TTP_XOR_WriteProcessMemory_728c {
  strings:
    $key_728c = { 25 fe [2] 17 dc [2] 11 e9 [2] 3f e9 [2] 00 f5 }

  condition:
    any of them
}