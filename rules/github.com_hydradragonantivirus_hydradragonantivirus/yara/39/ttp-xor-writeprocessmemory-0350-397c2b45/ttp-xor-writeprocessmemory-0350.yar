rule TTP_XOR_WriteProcessMemory_0350 {
  strings:
    $key_0350 = { 54 22 [2] 66 00 [2] 60 35 [2] 4e 35 [2] 71 29 }

  condition:
    any of them
}