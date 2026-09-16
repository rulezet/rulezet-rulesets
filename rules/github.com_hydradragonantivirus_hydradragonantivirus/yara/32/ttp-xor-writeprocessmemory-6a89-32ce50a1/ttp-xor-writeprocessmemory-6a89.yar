rule TTP_XOR_WriteProcessMemory_6a89 {
  strings:
    $key_6a89 = { 3d fb [2] 0f d9 [2] 09 ec [2] 27 ec [2] 18 f0 }

  condition:
    any of them
}