rule TTP_XOR_WriteProcessMemory_fcc1 {
  strings:
    $key_fcc1 = { ab b3 [2] 99 91 [2] 9f a4 [2] b1 a4 [2] 8e b8 }

  condition:
    any of them
}