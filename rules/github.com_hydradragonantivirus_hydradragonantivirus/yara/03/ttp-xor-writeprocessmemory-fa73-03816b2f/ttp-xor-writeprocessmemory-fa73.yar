rule TTP_XOR_WriteProcessMemory_fa73 {
  strings:
    $key_fa73 = { ad 01 [2] 9f 23 [2] 99 16 [2] b7 16 [2] 88 0a }

  condition:
    any of them
}