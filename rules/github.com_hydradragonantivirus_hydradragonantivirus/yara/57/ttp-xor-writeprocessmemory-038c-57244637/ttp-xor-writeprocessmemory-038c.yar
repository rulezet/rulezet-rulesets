rule TTP_XOR_WriteProcessMemory_038c {
  strings:
    $key_038c = { 54 fe [2] 66 dc [2] 60 e9 [2] 4e e9 [2] 71 f5 }

  condition:
    any of them
}