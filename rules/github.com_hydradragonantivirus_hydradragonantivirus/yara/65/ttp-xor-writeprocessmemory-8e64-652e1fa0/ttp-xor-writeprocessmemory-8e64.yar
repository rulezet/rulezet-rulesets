rule TTP_XOR_WriteProcessMemory_8e64 {
  strings:
    $key_8e64 = { d9 16 [2] eb 34 [2] ed 01 [2] c3 01 [2] fc 1d }

  condition:
    any of them
}