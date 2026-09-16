rule TTP_XOR_WriteProcessMemory_0378 {
  strings:
    $key_0378 = { 54 0a [2] 66 28 [2] 60 1d [2] 4e 1d [2] 71 01 }

  condition:
    any of them
}