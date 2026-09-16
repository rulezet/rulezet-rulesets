rule TTP_XOR_WriteProcessMemory_fa64 {
  strings:
    $key_fa64 = { ad 16 [2] 9f 34 [2] 99 01 [2] b7 01 [2] 88 1d }

  condition:
    any of them
}