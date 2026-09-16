rule TTP_XOR_WriteProcessMemory_558c {
  strings:
    $key_558c = { 02 fe [2] 30 dc [2] 36 e9 [2] 18 e9 [2] 27 f5 }

  condition:
    any of them
}