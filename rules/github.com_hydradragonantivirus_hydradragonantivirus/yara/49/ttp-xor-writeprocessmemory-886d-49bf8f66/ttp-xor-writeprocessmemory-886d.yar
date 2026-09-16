rule TTP_XOR_WriteProcessMemory_886d {
  strings:
    $key_886d = { df 1f [2] ed 3d [2] eb 08 [2] c5 08 [2] fa 14 }

  condition:
    any of them
}