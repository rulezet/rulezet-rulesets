rule TTP_XOR_WriteProcessMemory_88dd {
  strings:
    $key_88dd = { df af [2] ed 8d [2] eb b8 [2] c5 b8 [2] fa a4 }

  condition:
    any of them
}