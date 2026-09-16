rule TTP_XOR_WriteProcessMemory_7ce0 {
  strings:
    $key_7ce0 = { 2b 92 [2] 19 b0 [2] 1f 85 [2] 31 85 [2] 0e 99 }

  condition:
    any of them
}