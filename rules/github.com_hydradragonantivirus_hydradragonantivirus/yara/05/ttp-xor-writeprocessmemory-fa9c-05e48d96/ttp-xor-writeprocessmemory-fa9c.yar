rule TTP_XOR_WriteProcessMemory_fa9c {
  strings:
    $key_fa9c = { ad ee [2] 9f cc [2] 99 f9 [2] b7 f9 [2] 88 e5 }

  condition:
    any of them
}