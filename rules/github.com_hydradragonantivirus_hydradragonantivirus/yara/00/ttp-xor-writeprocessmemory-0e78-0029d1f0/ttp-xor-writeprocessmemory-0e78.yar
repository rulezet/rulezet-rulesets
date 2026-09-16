rule TTP_XOR_WriteProcessMemory_0e78 {
  strings:
    $key_0e78 = { 59 0a [2] 6b 28 [2] 6d 1d [2] 43 1d [2] 7c 01 }

  condition:
    any of them
}