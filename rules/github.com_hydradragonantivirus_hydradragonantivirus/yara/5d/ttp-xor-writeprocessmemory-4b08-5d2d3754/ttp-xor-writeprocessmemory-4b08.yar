rule TTP_XOR_WriteProcessMemory_4b08 {
  strings:
    $key_4b08 = { 1c 7a [2] 2e 58 [2] 28 6d [2] 06 6d [2] 39 71 }

  condition:
    any of them
}