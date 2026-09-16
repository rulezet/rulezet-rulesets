rule TTP_XOR_WriteProcessMemory_c8d6 {
  strings:
    $key_c8d6 = { 9f a4 [2] ad 86 [2] ab b3 [2] 85 b3 [2] ba af }

  condition:
    any of them
}