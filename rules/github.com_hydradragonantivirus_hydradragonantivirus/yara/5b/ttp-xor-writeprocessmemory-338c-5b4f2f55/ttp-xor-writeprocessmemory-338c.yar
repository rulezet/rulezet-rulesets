rule TTP_XOR_WriteProcessMemory_338c {
  strings:
    $key_338c = { 64 fe [2] 56 dc [2] 50 e9 [2] 7e e9 [2] 41 f5 }

  condition:
    any of them
}