rule TTP_XOR_WriteProcessMemory_d389 {
  strings:
    $key_d389 = { 84 fb [2] b6 d9 [2] b0 ec [2] 9e ec [2] a1 f0 }

  condition:
    any of them
}