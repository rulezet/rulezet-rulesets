rule TTP_XOR_WriteProcessMemory_fa17 {
  strings:
    $key_fa17 = { ad 65 [2] 9f 47 [2] 99 72 [2] b7 72 [2] 88 6e }

  condition:
    any of them
}