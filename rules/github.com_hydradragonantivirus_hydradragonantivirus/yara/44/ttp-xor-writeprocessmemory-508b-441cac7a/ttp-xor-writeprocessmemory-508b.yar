rule TTP_XOR_WriteProcessMemory_508b {
  strings:
    $key_508b = { 07 f9 [2] 35 db [2] 33 ee [2] 1d ee [2] 22 f2 }

  condition:
    any of them
}