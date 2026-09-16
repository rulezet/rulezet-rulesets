rule TTP_XOR_WriteProcessMemory_fa46 {
  strings:
    $key_fa46 = { ad 34 [2] 9f 16 [2] 99 23 [2] b7 23 [2] 88 3f }

  condition:
    any of them
}