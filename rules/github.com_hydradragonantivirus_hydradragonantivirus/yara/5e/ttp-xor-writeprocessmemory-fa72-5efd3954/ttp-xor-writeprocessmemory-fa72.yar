rule TTP_XOR_WriteProcessMemory_fa72 {
  strings:
    $key_fa72 = { ad 00 [2] 9f 22 [2] 99 17 [2] b7 17 [2] 88 0b }

  condition:
    any of them
}