rule TTP_XOR_WriteProcessMemory_0f78 {
  strings:
    $key_0f78 = { 58 0a [2] 6a 28 [2] 6c 1d [2] 42 1d [2] 7d 01 }

  condition:
    any of them
}