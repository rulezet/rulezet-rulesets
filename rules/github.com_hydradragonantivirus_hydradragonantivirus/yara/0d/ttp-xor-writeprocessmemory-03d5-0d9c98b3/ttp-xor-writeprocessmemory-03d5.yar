rule TTP_XOR_WriteProcessMemory_03d5 {
  strings:
    $key_03d5 = { 54 a7 [2] 66 85 [2] 60 b0 [2] 4e b0 [2] 71 ac }

  condition:
    any of them
}