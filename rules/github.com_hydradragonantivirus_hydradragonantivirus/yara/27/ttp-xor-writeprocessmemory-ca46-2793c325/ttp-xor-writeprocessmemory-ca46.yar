rule TTP_XOR_WriteProcessMemory_ca46 {
  strings:
    $key_ca46 = { 9d 34 [2] af 16 [2] a9 23 [2] 87 23 [2] b8 3f }

  condition:
    any of them
}