rule TTP_XOR_WriteProcessMemory_fa02 {
  strings:
    $key_fa02 = { ad 70 [2] 9f 52 [2] 99 67 [2] b7 67 [2] 88 7b }

  condition:
    any of them
}