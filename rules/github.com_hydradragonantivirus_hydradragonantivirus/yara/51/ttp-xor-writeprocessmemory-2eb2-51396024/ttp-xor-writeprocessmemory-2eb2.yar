rule TTP_XOR_WriteProcessMemory_2eb2 {
  strings:
    $key_2eb2 = { 79 c0 [2] 4b e2 [2] 4d d7 [2] 63 d7 [2] 5c cb }

  condition:
    any of them
}