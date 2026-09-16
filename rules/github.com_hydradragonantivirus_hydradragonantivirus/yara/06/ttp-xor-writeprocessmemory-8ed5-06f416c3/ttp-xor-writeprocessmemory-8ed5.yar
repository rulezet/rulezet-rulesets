rule TTP_XOR_WriteProcessMemory_8ed5 {
  strings:
    $key_8ed5 = { d9 a7 [2] eb 85 [2] ed b0 [2] c3 b0 [2] fc ac }

  condition:
    any of them
}