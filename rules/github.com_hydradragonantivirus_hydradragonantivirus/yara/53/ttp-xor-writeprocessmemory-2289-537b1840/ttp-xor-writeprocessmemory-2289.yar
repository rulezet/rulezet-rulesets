rule TTP_XOR_WriteProcessMemory_2289 {
  strings:
    $key_2289 = { 75 fb [2] 47 d9 [2] 41 ec [2] 6f ec [2] 50 f0 }

  condition:
    any of them
}