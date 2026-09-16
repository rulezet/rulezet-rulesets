rule TTP_XOR_WriteProcessMemory_279c {
  strings:
    $key_279c = { 70 ee [2] 42 cc [2] 44 f9 [2] 6a f9 [2] 55 e5 }

  condition:
    any of them
}