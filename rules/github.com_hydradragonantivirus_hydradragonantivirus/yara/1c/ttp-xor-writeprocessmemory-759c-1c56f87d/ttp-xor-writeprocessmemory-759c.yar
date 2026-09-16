rule TTP_XOR_WriteProcessMemory_759c {
  strings:
    $key_759c = { 22 ee [2] 10 cc [2] 16 f9 [2] 38 f9 [2] 07 e5 }

  condition:
    any of them
}