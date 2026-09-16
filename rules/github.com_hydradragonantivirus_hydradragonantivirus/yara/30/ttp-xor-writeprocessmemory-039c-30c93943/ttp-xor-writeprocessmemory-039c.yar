rule TTP_XOR_WriteProcessMemory_039c {
  strings:
    $key_039c = { 54 ee [2] 66 cc [2] 60 f9 [2] 4e f9 [2] 71 e5 }

  condition:
    any of them
}