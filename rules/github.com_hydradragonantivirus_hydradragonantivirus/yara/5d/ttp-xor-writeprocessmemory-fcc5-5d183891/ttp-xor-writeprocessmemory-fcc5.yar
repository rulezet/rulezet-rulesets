rule TTP_XOR_WriteProcessMemory_fcc5 {
  strings:
    $key_fcc5 = { ab b7 [2] 99 95 [2] 9f a0 [2] b1 a0 [2] 8e bc }

  condition:
    any of them
}