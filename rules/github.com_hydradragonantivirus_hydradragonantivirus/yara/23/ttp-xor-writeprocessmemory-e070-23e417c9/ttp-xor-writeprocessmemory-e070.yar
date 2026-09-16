rule TTP_XOR_WriteProcessMemory_e070 {
  strings:
    $key_e070 = { b7 02 [2] 85 20 [2] 83 15 [2] ad 15 [2] 92 09 }

  condition:
    any of them
}