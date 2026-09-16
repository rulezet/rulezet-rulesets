rule TTP_XOR_WriteProcessMemory_178c {
  strings:
    $key_178c = { 40 fe [2] 72 dc [2] 74 e9 [2] 5a e9 [2] 65 f5 }

  condition:
    any of them
}