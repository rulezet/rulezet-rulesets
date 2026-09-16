rule TTP_XOR_WriteProcessMemory_c8d5 {
  strings:
    $key_c8d5 = { 9f a7 [2] ad 85 [2] ab b0 [2] 85 b0 [2] ba ac }

  condition:
    any of them
}