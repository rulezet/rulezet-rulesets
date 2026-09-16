rule TTP_XOR_WriteProcessMemory_8866 {
  strings:
    $key_8866 = { df 14 [2] ed 36 [2] eb 03 [2] c5 03 [2] fa 1f }

  condition:
    any of them
}