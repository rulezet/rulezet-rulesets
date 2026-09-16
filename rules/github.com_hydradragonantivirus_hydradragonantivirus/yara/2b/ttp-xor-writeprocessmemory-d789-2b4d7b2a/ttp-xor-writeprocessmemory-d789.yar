rule TTP_XOR_WriteProcessMemory_d789 {
  strings:
    $key_d789 = { 80 fb [2] b2 d9 [2] b4 ec [2] 9a ec [2] a5 f0 }

  condition:
    any of them
}