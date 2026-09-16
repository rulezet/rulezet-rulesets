rule TTP_XOR_WriteProcessMemory_3e89 {
  strings:
    $key_3e89 = { 69 fb [2] 5b d9 [2] 5d ec [2] 73 ec [2] 4c f0 }

  condition:
    any of them
}