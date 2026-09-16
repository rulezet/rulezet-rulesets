rule TTP_XOR_WriteProcessMemory_5303 {
  strings:
    $key_5303 = { 04 71 [2] 36 53 [2] 30 66 [2] 1e 66 [2] 21 7a }

  condition:
    any of them
}