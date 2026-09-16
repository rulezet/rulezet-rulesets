rule TTP_XOR_WriteProcessMemory_8828 {
  strings:
    $key_8828 = { df 5a [2] ed 78 [2] eb 4d [2] c5 4d [2] fa 51 }

  condition:
    any of them
}