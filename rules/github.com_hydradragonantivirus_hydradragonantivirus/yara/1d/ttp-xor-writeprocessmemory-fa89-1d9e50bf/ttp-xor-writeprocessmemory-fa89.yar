rule TTP_XOR_WriteProcessMemory_fa89 {
  strings:
    $key_fa89 = { ad fb [2] 9f d9 [2] 99 ec [2] b7 ec [2] 88 f0 }

  condition:
    any of them
}