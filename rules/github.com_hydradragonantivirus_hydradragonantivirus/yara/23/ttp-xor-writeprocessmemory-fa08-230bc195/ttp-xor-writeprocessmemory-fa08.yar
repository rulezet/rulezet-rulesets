rule TTP_XOR_WriteProcessMemory_fa08 {
  strings:
    $key_fa08 = { ad 7a [2] 9f 58 [2] 99 6d [2] b7 6d [2] 88 71 }

  condition:
    any of them
}