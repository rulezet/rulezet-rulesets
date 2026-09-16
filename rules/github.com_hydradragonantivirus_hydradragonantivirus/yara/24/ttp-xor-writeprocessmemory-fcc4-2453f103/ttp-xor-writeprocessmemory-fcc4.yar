rule TTP_XOR_WriteProcessMemory_fcc4 {
  strings:
    $key_fcc4 = { ab b6 [2] 99 94 [2] 9f a1 [2] b1 a1 [2] 8e bd }

  condition:
    any of them
}