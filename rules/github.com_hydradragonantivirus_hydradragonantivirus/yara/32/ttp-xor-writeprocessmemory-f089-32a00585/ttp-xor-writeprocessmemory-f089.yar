rule TTP_XOR_WriteProcessMemory_f089 {
  strings:
    $key_f089 = { a7 fb [2] 95 d9 [2] 93 ec [2] bd ec [2] 82 f0 }

  condition:
    any of them
}