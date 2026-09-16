rule TTP_XOR_WriteProcessMemory_5a9c {
  strings:
    $key_5a9c = { 0d ee [2] 3f cc [2] 39 f9 [2] 17 f9 [2] 28 e5 }

  condition:
    any of them
}