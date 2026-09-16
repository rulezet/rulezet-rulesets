rule TTP_XOR_WriteProcessMemory_faf1 {
  strings:
    $key_faf1 = { ad 83 [2] 9f a1 [2] 99 94 [2] b7 94 [2] 88 88 }

  condition:
    any of them
}