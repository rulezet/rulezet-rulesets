rule TTP_XOR_WriteProcessMemory_b9a9 {
  strings:
    $key_b9a9 = { ee db [2] dc f9 [2] da cc [2] f4 cc [2] cb d0 }

  condition:
    any of them
}