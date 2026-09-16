rule TTP_XOR_WriteProcessMemory_883d {
  strings:
    $key_883d = { df 4f [2] ed 6d [2] eb 58 [2] c5 58 [2] fa 44 }

  condition:
    any of them
}