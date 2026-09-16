rule TTP_XOR_WriteProcessMemory_c8d4 {
  strings:
    $key_c8d4 = { 9f a6 [2] ad 84 [2] ab b1 [2] 85 b1 [2] ba ad }

  condition:
    any of them
}