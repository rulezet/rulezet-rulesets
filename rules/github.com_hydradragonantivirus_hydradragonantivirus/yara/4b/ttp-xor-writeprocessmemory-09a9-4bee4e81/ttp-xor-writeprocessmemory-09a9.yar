rule TTP_XOR_WriteProcessMemory_09a9 {
  strings:
    $key_09a9 = { 5e db [2] 6c f9 [2] 6a cc [2] 44 cc [2] 7b d0 }

  condition:
    any of them
}