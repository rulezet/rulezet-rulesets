rule TTP_XOR_WriteProcessMemory_ecc0 {
  strings:
    $key_ecc0 = { bb b2 [2] 89 90 [2] 8f a5 [2] a1 a5 [2] 9e b9 }

  condition:
    any of them
}