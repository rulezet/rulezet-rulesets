rule TTP_XOR_WriteProcessMemory_fa61 {
  strings:
    $key_fa61 = { ad 13 [2] 9f 31 [2] 99 04 [2] b7 04 [2] 88 18 }

  condition:
    any of them
}