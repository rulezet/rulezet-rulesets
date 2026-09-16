rule TTP_XOR_WriteProcessMemory_009c {
  strings:
    $key_009c = { 57 ee [2] 65 cc [2] 63 f9 [2] 4d f9 [2] 72 e5 }

  condition:
    any of them
}