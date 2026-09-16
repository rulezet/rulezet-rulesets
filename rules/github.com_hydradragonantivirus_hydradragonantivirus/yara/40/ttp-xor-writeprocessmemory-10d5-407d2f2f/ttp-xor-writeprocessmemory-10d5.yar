rule TTP_XOR_WriteProcessMemory_10d5 {
  strings:
    $key_10d5 = { 47 a7 [2] 75 85 [2] 73 b0 [2] 5d b0 [2] 62 ac }

  condition:
    any of them
}