rule TTP_XOR_WriteProcessMemory_eb89 {
  strings:
    $key_eb89 = { bc fb [2] 8e d9 [2] 88 ec [2] a6 ec [2] 99 f0 }

  condition:
    any of them
}