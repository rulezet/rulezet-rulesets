rule TTP_XOR_WriteProcessMemory_feb2 {
  strings:
    $key_feb2 = { a9 c0 [2] 9b e2 [2] 9d d7 [2] b3 d7 [2] 8c cb }

  condition:
    any of them
}