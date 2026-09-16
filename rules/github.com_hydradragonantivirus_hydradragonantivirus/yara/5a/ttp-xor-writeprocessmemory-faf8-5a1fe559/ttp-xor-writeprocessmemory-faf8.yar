rule TTP_XOR_WriteProcessMemory_faf8 {
  strings:
    $key_faf8 = { ad 8a [2] 9f a8 [2] 99 9d [2] b7 9d [2] 88 81 }

  condition:
    any of them
}