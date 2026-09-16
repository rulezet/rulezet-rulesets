rule TTP_XOR_WriteProcessMemory_428c {
  strings:
    $key_428c = { 15 fe [2] 27 dc [2] 21 e9 [2] 0f e9 [2] 30 f5 }

  condition:
    any of them
}