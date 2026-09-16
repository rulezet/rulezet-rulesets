rule TTP_XOR_WriteProcessMemory_8789 {
  strings:
    $key_8789 = { d0 fb [2] e2 d9 [2] e4 ec [2] ca ec [2] f5 f0 }

  condition:
    any of them
}