rule TTP_XOR_WriteProcessMemory_d289 {
  strings:
    $key_d289 = { 85 fb [2] b7 d9 [2] b1 ec [2] 9f ec [2] a0 f0 }

  condition:
    any of them
}