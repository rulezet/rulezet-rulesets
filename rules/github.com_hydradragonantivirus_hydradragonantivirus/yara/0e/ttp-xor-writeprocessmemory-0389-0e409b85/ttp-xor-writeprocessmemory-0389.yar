rule TTP_XOR_WriteProcessMemory_0389 {
  strings:
    $key_0389 = { 54 fb [2] 66 d9 [2] 60 ec [2] 4e ec [2] 71 f0 }

  condition:
    any of them
}