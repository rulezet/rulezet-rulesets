rule TTP_XOR_WriteProcessMemory_0308 {
  strings:
    $key_0308 = { 54 7a [2] 66 58 [2] 60 6d [2] 4e 6d [2] 71 71 }

  condition:
    any of them
}