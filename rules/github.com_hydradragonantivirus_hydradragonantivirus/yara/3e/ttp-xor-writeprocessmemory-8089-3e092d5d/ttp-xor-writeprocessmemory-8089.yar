rule TTP_XOR_WriteProcessMemory_8089 {
  strings:
    $key_8089 = { d7 fb [2] e5 d9 [2] e3 ec [2] cd ec [2] f2 f0 }

  condition:
    any of them
}