rule TTP_XOR_WriteProcessMemory_059c {
  strings:
    $key_059c = { 52 ee [2] 60 cc [2] 66 f9 [2] 48 f9 [2] 77 e5 }

  condition:
    any of them
}