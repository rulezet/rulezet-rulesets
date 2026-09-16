rule TTP_XOR_WriteProcessMemory_e08b {
  strings:
    $key_e08b = { b7 f9 [2] 85 db [2] 83 ee [2] ad ee [2] 92 f2 }

  condition:
    any of them
}