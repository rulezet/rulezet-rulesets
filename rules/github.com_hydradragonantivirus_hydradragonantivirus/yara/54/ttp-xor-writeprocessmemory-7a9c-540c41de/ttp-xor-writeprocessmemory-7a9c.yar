rule TTP_XOR_WriteProcessMemory_7a9c {
  strings:
    $key_7a9c = { 2d ee [2] 1f cc [2] 19 f9 [2] 37 f9 [2] 08 e5 }

  condition:
    any of them
}