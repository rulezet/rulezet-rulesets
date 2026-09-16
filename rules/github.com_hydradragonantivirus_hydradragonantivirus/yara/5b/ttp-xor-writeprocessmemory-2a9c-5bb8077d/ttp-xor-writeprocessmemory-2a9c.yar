rule TTP_XOR_WriteProcessMemory_2a9c {
  strings:
    $key_2a9c = { 7d ee [2] 4f cc [2] 49 f9 [2] 67 f9 [2] 58 e5 }

  condition:
    any of them
}