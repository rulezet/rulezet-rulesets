rule TTP_XOR_WriteProcessMemory_b987 {
  strings:
    $key_b987 = { ee f5 [2] dc d7 [2] da e2 [2] f4 e2 [2] cb fe }

  condition:
    any of them
}