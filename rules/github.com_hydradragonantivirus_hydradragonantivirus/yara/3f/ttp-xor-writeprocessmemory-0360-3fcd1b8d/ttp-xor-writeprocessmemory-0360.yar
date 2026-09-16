rule TTP_XOR_WriteProcessMemory_0360 {
  strings:
    $key_0360 = { 54 12 [2] 66 30 [2] 60 05 [2] 4e 05 [2] 71 19 }

  condition:
    any of them
}