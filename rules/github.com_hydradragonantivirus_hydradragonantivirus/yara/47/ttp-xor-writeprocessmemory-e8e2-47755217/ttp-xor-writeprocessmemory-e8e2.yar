rule TTP_XOR_WriteProcessMemory_e8e2 {
  strings:
    $key_e8e2 = { bf 90 [2] 8d b2 [2] 8b 87 [2] a5 87 [2] 9a 9b }

  condition:
    any of them
}