rule TTP_XOR_WriteProcessMemory_8838 {
  strings:
    $key_8838 = { df 4a [2] ed 68 [2] eb 5d [2] c5 5d [2] fa 41 }

  condition:
    any of them
}