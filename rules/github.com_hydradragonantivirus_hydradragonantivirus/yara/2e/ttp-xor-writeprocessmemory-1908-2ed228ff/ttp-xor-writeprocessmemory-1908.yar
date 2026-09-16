rule TTP_XOR_WriteProcessMemory_1908 {
  strings:
    $key_1908 = { 4e 7a [2] 7c 58 [2] 7a 6d [2] 54 6d [2] 6b 71 }

  condition:
    any of them
}