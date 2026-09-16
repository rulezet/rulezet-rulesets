rule TTP_XOR_WriteProcessMemory_359c {
  strings:
    $key_359c = { 62 ee [2] 50 cc [2] 56 f9 [2] 78 f9 [2] 47 e5 }

  condition:
    any of them
}