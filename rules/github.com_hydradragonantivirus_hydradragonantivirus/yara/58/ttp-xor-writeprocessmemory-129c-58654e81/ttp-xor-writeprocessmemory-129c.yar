rule TTP_XOR_WriteProcessMemory_129c {
  strings:
    $key_129c = { 45 ee [2] 77 cc [2] 71 f9 [2] 5f f9 [2] 60 e5 }

  condition:
    any of them
}