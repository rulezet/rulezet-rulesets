rule TTP_XOR_WriteProcessMemory_7a89 {
  strings:
    $key_7a89 = { 2d fb [2] 1f d9 [2] 19 ec [2] 37 ec [2] 08 f0 }

  condition:
    any of them
}