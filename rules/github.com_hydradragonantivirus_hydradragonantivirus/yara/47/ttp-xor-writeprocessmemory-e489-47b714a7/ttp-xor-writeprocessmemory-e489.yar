rule TTP_XOR_WriteProcessMemory_e489 {
  strings:
    $key_e489 = { b3 fb [2] 81 d9 [2] 87 ec [2] a9 ec [2] 96 f0 }

  condition:
    any of them
}