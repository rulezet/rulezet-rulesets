rule TTP_XOR_WriteProcessMemory_6289 {
  strings:
    $key_6289 = { 35 fb [2] 07 d9 [2] 01 ec [2] 2f ec [2] 10 f0 }

  condition:
    any of them
}