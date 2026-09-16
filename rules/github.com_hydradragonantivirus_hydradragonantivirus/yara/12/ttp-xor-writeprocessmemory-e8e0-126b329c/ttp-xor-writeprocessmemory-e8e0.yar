rule TTP_XOR_WriteProcessMemory_e8e0 {
  strings:
    $key_e8e0 = { bf 92 [2] 8d b0 [2] 8b 85 [2] a5 85 [2] 9a 99 }

  condition:
    any of them
}