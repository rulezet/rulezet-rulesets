rule TTP_XOR_WriteProcessMemory_88a9 {
  strings:
    $key_88a9 = { df db [2] ed f9 [2] eb cc [2] c5 cc [2] fa d0 }

  condition:
    any of them
}