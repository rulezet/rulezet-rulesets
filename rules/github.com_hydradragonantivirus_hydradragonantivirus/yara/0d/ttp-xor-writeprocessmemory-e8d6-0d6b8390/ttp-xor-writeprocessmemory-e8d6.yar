rule TTP_XOR_WriteProcessMemory_e8d6 {
  strings:
    $key_e8d6 = { bf a4 [2] 8d 86 [2] 8b b3 [2] a5 b3 [2] 9a af }

  condition:
    any of them
}