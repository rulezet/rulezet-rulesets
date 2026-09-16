rule TTP_XOR_WriteProcessMemory_458c {
  strings:
    $key_458c = { 12 fe [2] 20 dc [2] 26 e9 [2] 08 e9 [2] 37 f5 }

  condition:
    any of them
}