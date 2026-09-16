rule TTP_XOR_WriteProcessMemory_8854 {
  strings:
    $key_8854 = { df 26 [2] ed 04 [2] eb 31 [2] c5 31 [2] fa 2d }

  condition:
    any of them
}