rule TTP_XOR_WriteProcessMemory_2489 {
  strings:
    $key_2489 = { 73 fb [2] 41 d9 [2] 47 ec [2] 69 ec [2] 56 f0 }

  condition:
    any of them
}