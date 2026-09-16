rule TTP_XOR_WriteProcessMemory_5310 {
  strings:
    $key_5310 = { 04 62 [2] 36 40 [2] 30 75 [2] 1e 75 [2] 21 69 }

  condition:
    any of them
}