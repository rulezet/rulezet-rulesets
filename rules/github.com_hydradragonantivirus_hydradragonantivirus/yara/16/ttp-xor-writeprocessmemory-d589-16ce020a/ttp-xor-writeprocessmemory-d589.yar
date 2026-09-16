rule TTP_XOR_WriteProcessMemory_d589 {
  strings:
    $key_d589 = { 82 fb [2] b0 d9 [2] b6 ec [2] 98 ec [2] a7 f0 }

  condition:
    any of them
}