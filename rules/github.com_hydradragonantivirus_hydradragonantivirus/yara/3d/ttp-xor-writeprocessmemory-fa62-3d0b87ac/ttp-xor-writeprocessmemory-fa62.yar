rule TTP_XOR_WriteProcessMemory_fa62 {
  strings:
    $key_fa62 = { ad 10 [2] 9f 32 [2] 99 07 [2] b7 07 [2] 88 1b }

  condition:
    any of them
}