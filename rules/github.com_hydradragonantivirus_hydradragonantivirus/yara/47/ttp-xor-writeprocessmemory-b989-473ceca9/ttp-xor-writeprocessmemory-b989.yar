rule TTP_XOR_WriteProcessMemory_b989 {
  strings:
    $key_b989 = { ee fb [2] dc d9 [2] da ec [2] f4 ec [2] cb f0 }

  condition:
    any of them
}