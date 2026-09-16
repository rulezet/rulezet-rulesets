rule TTP_XOR_WriteProcessMemory_159c {
  strings:
    $key_159c = { 42 ee [2] 70 cc [2] 76 f9 [2] 58 f9 [2] 67 e5 }

  condition:
    any of them
}