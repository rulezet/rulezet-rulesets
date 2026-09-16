rule TTP_XOR_WriteProcessMemory_209c {
  strings:
    $key_209c = { 77 ee [2] 45 cc [2] 43 f9 [2] 6d f9 [2] 52 e5 }

  condition:
    any of them
}