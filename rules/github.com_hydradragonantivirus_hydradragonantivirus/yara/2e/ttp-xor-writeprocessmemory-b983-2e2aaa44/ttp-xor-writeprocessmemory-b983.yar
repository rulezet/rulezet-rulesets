rule TTP_XOR_WriteProcessMemory_b983 {
  strings:
    $key_b983 = { ee f1 [2] dc d3 [2] da e6 [2] f4 e6 [2] cb fa }

  condition:
    any of them
}