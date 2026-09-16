rule TTP_XOR_WriteProcessMemory_3ce0 {
  strings:
    $key_3ce0 = { 6b 92 [2] 59 b0 [2] 5f 85 [2] 71 85 [2] 4e 99 }

  condition:
    any of them
}