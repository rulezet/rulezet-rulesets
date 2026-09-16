rule TTP_XOR_WriteProcessMemory_248c {
  strings:
    $key_248c = { 73 fe [2] 41 dc [2] 47 e9 [2] 69 e9 [2] 56 f5 }

  condition:
    any of them
}