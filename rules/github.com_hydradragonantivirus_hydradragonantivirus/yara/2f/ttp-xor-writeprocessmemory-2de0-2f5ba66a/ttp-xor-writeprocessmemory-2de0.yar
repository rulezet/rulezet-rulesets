rule TTP_XOR_WriteProcessMemory_2de0 {
  strings:
    $key_2de0 = { 7a 92 [2] 48 b0 [2] 4e 85 [2] 60 85 [2] 5f 99 }

  condition:
    any of them
}