rule TTP_XOR_WriteProcessMemory_8e61 {
  strings:
    $key_8e61 = { d9 13 [2] eb 31 [2] ed 04 [2] c3 04 [2] fc 18 }

  condition:
    any of them
}