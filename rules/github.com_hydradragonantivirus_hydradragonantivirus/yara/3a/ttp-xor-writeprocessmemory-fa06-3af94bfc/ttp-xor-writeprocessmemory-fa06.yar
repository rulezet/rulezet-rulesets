rule TTP_XOR_WriteProcessMemory_fa06 {
  strings:
    $key_fa06 = { ad 74 [2] 9f 56 [2] 99 63 [2] b7 63 [2] 88 7f }

  condition:
    any of them
}