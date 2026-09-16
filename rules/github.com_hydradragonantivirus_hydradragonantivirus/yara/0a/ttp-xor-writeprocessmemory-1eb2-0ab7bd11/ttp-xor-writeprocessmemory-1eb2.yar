rule TTP_XOR_WriteProcessMemory_1eb2 {
  strings:
    $key_1eb2 = { 49 c0 [2] 7b e2 [2] 7d d7 [2] 53 d7 [2] 6c cb }

  condition:
    any of them
}