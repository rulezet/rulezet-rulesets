rule TTP_XOR_WriteProcessMemory_0289 {
  strings:
    $key_0289 = { 55 fb [2] 67 d9 [2] 61 ec [2] 4f ec [2] 70 f0 }

  condition:
    any of them
}