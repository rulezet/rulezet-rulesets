rule TTP_XOR_WriteProcessMemory_7408 {
  strings:
    $key_7408 = { 23 7a [2] 11 58 [2] 17 6d [2] 39 6d [2] 06 71 }

  condition:
    any of them
}