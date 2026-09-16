rule TTP_XOR_WriteProcessMemory_c8d2 {
  strings:
    $key_c8d2 = { 9f a0 [2] ad 82 [2] ab b7 [2] 85 b7 [2] ba ab }

  condition:
    any of them
}