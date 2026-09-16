rule TTP_XOR_WriteProcessMemory_fcc0 {
  strings:
    $key_fcc0 = { ab b2 [2] 99 90 [2] 9f a5 [2] b1 a5 [2] 8e b9 }

  condition:
    any of them
}