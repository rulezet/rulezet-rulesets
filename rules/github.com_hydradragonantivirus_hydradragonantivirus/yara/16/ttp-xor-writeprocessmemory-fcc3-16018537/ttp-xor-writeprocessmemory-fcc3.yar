rule TTP_XOR_WriteProcessMemory_fcc3 {
  strings:
    $key_fcc3 = { ab b1 [2] 99 93 [2] 9f a6 [2] b1 a6 [2] 8e ba }

  condition:
    any of them
}