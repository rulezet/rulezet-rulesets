rule TTP_XOR_WriteProcessMemory_fa16 {
  strings:
    $key_fa16 = { ad 64 [2] 9f 46 [2] 99 73 [2] b7 73 [2] 88 6f }

  condition:
    any of them
}