rule TTP_XOR_WriteProcessMemory_2e89 {
  strings:
    $key_2e89 = { 79 fb [2] 4b d9 [2] 4d ec [2] 63 ec [2] 5c f0 }

  condition:
    any of them
}