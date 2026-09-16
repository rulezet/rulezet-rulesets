rule TTP_XOR_WriteProcessMemory_02d5 {
  strings:
    $key_02d5 = { 55 a7 [2] 67 85 [2] 61 b0 [2] 4f b0 [2] 70 ac }

  condition:
    any of them
}