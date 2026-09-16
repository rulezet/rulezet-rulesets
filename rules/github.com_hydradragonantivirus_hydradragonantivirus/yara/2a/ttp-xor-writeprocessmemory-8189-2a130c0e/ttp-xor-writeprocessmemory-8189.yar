rule TTP_XOR_WriteProcessMemory_8189 {
  strings:
    $key_8189 = { d6 fb [2] e4 d9 [2] e2 ec [2] cc ec [2] f3 f0 }

  condition:
    any of them
}