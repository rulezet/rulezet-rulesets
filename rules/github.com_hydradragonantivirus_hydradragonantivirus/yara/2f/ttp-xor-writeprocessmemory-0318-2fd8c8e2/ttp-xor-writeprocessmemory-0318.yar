rule TTP_XOR_WriteProcessMemory_0318 {
  strings:
    $key_0318 = { 54 6a [2] 66 48 [2] 60 7d [2] 4e 7d [2] 71 61 }

  condition:
    any of them
}