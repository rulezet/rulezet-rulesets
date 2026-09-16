rule TTP_XOR_WriteProcessMemory_0908 {
  strings:
    $key_0908 = { 5e 7a [2] 6c 58 [2] 6a 6d [2] 44 6d [2] 7b 71 }

  condition:
    any of them
}