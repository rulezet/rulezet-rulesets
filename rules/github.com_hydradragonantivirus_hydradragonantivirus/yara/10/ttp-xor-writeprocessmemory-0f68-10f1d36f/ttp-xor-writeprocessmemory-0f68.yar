rule TTP_XOR_WriteProcessMemory_0f68 {
  strings:
    $key_0f68 = { 58 1a [2] 6a 38 [2] 6c 0d [2] 42 0d [2] 7d 11 }

  condition:
    any of them
}