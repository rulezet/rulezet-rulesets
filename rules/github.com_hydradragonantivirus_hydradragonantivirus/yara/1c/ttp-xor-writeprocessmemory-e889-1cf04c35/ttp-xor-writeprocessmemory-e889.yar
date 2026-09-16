rule TTP_XOR_WriteProcessMemory_e889 {
  strings:
    $key_e889 = { bf fb [2] 8d d9 [2] 8b ec [2] a5 ec [2] 9a f0 }

  condition:
    any of them
}