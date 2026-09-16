rule TTP_XOR_WriteProcessMemory_8e36 {
  strings:
    $key_8e36 = { d9 44 [2] eb 66 [2] ed 53 [2] c3 53 [2] fc 4f }

  condition:
    any of them
}