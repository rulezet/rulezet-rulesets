rule TTP_XOR_WriteProcessMemory_179c {
  strings:
    $key_179c = { 40 ee [2] 72 cc [2] 74 f9 [2] 5a f9 [2] 65 e5 }

  condition:
    any of them
}