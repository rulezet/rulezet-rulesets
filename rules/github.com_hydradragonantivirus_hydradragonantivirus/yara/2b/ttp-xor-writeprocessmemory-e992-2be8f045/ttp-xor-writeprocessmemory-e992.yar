rule TTP_XOR_WriteProcessMemory_e992 {
  strings:
    $key_e992 = { be e0 [2] 8c c2 [2] 8a f7 [2] a4 f7 [2] 9b eb }

  condition:
    any of them
}