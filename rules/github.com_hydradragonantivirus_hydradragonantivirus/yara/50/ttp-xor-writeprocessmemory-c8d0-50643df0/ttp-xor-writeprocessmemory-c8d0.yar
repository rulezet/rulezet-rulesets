rule TTP_XOR_WriteProcessMemory_c8d0 {
  strings:
    $key_c8d0 = { 9f a2 [2] ad 80 [2] ab b5 [2] 85 b5 [2] ba a9 }

  condition:
    any of them
}