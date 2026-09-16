rule TTP_XOR_WriteProcessMemory_88a2 {
  strings:
    $key_88a2 = { df d0 [2] ed f2 [2] eb c7 [2] c5 c7 [2] fa db }

  condition:
    any of them
}