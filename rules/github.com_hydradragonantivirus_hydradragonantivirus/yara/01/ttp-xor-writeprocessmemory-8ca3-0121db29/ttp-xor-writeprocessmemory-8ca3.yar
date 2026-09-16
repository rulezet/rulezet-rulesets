rule TTP_XOR_WriteProcessMemory_8ca3 {
  strings:
    $key_8ca3 = { db d1 [2] e9 f3 [2] ef c6 [2] c1 c6 [2] fe da }

  condition:
    any of them
}