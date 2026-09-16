rule TTP_XOR_WriteProcessMemory_ec89 {
  strings:
    $key_ec89 = { bb fb [2] 89 d9 [2] 8f ec [2] a1 ec [2] 9e f0 }

  condition:
    any of them
}