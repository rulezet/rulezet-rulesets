rule TTP_XOR_WriteProcessMemory_0168 {
  strings:
    $key_0168 = { 56 1a [2] 64 38 [2] 62 0d [2] 4c 0d [2] 73 11 }

  condition:
    any of them
}