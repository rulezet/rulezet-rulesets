rule TTP_XOR_WriteProcessMemory_779c {
  strings:
    $key_779c = { 20 ee [2] 12 cc [2] 14 f9 [2] 3a f9 [2] 05 e5 }

  condition:
    any of them
}