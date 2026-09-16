rule TTP_XOR_WriteProcessMemory_fce6 {
  strings:
    $key_fce6 = { ab 94 [2] 99 b6 [2] 9f 83 [2] b1 83 [2] 8e 9f }

  condition:
    any of them
}