rule TTP_XOR_WriteProcessMemory_5b08 {
  strings:
    $key_5b08 = { 0c 7a [2] 3e 58 [2] 38 6d [2] 16 6d [2] 29 71 }

  condition:
    any of them
}