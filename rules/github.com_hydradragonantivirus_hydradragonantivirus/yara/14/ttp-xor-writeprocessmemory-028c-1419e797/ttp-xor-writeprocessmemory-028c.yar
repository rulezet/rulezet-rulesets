rule TTP_XOR_WriteProcessMemory_028c {
  strings:
    $key_028c = { 55 fe [2] 67 dc [2] 61 e9 [2] 4f e9 [2] 70 f5 }

  condition:
    any of them
}