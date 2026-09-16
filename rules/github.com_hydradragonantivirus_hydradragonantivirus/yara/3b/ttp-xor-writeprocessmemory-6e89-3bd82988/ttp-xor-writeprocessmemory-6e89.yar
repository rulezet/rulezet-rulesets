rule TTP_XOR_WriteProcessMemory_6e89 {
  strings:
    $key_6e89 = { 39 fb [2] 0b d9 [2] 0d ec [2] 23 ec [2] 1c f0 }

  condition:
    any of them
}