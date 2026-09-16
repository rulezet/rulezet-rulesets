rule TTP_XOR_WriteProcessMemory_fa9d {
  strings:
    $key_fa9d = { ad ef [2] 9f cd [2] 99 f8 [2] b7 f8 [2] 88 e4 }

  condition:
    any of them
}