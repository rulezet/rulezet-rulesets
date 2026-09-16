rule TTP_XOR_WriteProcessMemory_8816 {
  strings:
    $key_8816 = { df 64 [2] ed 46 [2] eb 73 [2] c5 73 [2] fa 6f }

  condition:
    any of them
}