rule TTP_XOR_WriteProcessMemory_c189 {
  strings:
    $key_c189 = { 96 fb [2] a4 d9 [2] a2 ec [2] 8c ec [2] b3 f0 }

  condition:
    any of them
}