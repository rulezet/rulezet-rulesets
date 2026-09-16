rule TTP_XOR_WriteProcessMemory_5a08 {
  strings:
    $key_5a08 = { 0d 7a [2] 3f 58 [2] 39 6d [2] 17 6d [2] 28 71 }

  condition:
    any of them
}