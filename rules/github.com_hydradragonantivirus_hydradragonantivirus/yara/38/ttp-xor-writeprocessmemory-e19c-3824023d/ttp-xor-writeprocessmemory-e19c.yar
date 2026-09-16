rule TTP_XOR_WriteProcessMemory_e19c {
  strings:
    $key_e19c = { b6 ee [2] 84 cc [2] 82 f9 [2] ac f9 [2] 93 e5 }

  condition:
    any of them
}