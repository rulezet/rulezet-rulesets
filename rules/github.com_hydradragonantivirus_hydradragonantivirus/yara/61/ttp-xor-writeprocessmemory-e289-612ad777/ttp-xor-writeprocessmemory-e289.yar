rule TTP_XOR_WriteProcessMemory_e289 {
  strings:
    $key_e289 = { b5 fb [2] 87 d9 [2] 81 ec [2] af ec [2] 90 f0 }

  condition:
    any of them
}