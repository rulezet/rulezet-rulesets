rule TTP_XOR_WriteProcessMemory_329c {
  strings:
    $key_329c = { 65 ee [2] 57 cc [2] 51 f9 [2] 7f f9 [2] 40 e5 }

  condition:
    any of them
}