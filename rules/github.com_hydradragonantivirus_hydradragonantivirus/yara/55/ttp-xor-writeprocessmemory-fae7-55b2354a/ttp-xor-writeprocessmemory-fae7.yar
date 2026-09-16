rule TTP_XOR_WriteProcessMemory_fae7 {
  strings:
    $key_fae7 = { ad 95 [2] 9f b7 [2] 99 82 [2] b7 82 [2] 88 9e }

  condition:
    any of them
}