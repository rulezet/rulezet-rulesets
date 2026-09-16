rule TTP_XOR_WriteProcessMemory_8e89 {
  strings:
    $key_8e89 = { d9 fb [2] eb d9 [2] ed ec [2] c3 ec [2] fc f0 }

  condition:
    any of them
}