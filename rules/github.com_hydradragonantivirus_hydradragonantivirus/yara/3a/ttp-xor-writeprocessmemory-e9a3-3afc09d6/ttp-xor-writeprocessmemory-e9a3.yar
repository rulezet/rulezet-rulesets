rule TTP_XOR_WriteProcessMemory_e9a3 {
  strings:
    $key_e9a3 = { be d1 [2] 8c f3 [2] 8a c6 [2] a4 c6 [2] 9b da }

  condition:
    any of them
}