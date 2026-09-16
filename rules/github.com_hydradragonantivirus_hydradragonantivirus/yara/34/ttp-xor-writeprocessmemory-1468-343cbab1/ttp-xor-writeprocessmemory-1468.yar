rule TTP_XOR_WriteProcessMemory_1468 {
  strings:
    $key_1468 = { 43 1a [2] 71 38 [2] 77 0d [2] 59 0d [2] 66 11 }

  condition:
    any of them
}