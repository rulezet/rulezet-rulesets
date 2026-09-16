rule TTP_XOR_WriteProcessMemory_fa42 {
  strings:
    $key_fa42 = { ad 30 [2] 9f 12 [2] 99 27 [2] b7 27 [2] 88 3b }

  condition:
    any of them
}