rule TTP_XOR_WriteProcessMemory_6eb2 {
  strings:
    $key_6eb2 = { 39 c0 [2] 0b e2 [2] 0d d7 [2] 23 d7 [2] 1c cb }

  condition:
    any of them
}