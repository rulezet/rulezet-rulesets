rule TTP_XOR_WriteProcessMemory_88b8 {
  strings:
    $key_88b8 = { df ca [2] ed e8 [2] eb dd [2] c5 dd [2] fa c1 }

  condition:
    any of them
}