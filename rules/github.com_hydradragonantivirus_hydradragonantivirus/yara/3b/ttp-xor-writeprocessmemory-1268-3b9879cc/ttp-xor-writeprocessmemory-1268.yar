rule TTP_XOR_WriteProcessMemory_1268 {
  strings:
    $key_1268 = { 45 1a [2] 77 38 [2] 71 0d [2] 5f 0d [2] 60 11 }

  condition:
    any of them
}