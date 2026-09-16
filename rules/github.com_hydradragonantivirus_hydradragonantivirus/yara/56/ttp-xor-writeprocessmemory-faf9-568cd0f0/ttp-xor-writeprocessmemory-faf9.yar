rule TTP_XOR_WriteProcessMemory_faf9 {
  strings:
    $key_faf9 = { ad 8b [2] 9f a9 [2] 99 9c [2] b7 9c [2] 88 80 }

  condition:
    any of them
}