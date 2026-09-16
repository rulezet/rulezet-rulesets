rule TTP_XOR_WriteProcessMemory_fa53 {
  strings:
    $key_fa53 = { ad 21 [2] 9f 03 [2] 99 36 [2] b7 36 [2] 88 2a }

  condition:
    any of them
}