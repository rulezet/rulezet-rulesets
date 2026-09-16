rule TTP_XOR_WriteProcessMemory_1408 {
  strings:
    $key_1408 = { 43 7a [2] 71 58 [2] 77 6d [2] 59 6d [2] 66 71 }

  condition:
    any of them
}