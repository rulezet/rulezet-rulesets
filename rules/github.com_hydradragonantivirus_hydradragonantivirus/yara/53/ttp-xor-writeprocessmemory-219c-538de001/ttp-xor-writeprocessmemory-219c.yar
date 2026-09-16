rule TTP_XOR_WriteProcessMemory_219c {
  strings:
    $key_219c = { 76 ee [2] 44 cc [2] 42 f9 [2] 6c f9 [2] 53 e5 }

  condition:
    any of them
}