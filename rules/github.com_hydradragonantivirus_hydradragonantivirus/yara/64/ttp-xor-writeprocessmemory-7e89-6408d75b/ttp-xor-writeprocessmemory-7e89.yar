rule TTP_XOR_WriteProcessMemory_7e89 {
  strings:
    $key_7e89 = { 29 fb [2] 1b d9 [2] 1d ec [2] 33 ec [2] 0c f0 }

  condition:
    any of them
}