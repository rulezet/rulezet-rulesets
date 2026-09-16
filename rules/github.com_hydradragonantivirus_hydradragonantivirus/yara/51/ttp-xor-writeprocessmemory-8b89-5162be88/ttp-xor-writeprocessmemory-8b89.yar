rule TTP_XOR_WriteProcessMemory_8b89 {
  strings:
    $key_8b89 = { dc fb [2] ee d9 [2] e8 ec [2] c6 ec [2] f9 f0 }

  condition:
    any of them
}