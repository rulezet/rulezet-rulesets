rule TTP_XOR_WriteProcessMemory_e88b {
  strings:
    $key_e88b = { bf f9 [2] 8d db [2] 8b ee [2] a5 ee [2] 9a f2 }

  condition:
    any of them
}