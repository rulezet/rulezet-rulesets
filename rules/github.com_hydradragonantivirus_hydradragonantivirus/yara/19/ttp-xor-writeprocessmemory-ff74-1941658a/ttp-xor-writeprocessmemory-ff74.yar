rule TTP_XOR_WriteProcessMemory_ff74 {
  strings:
    $key_ff74 = { a8 06 [2] 9a 24 [2] 9c 11 [2] b2 11 [2] 8d 0d }

  condition:
    any of them
}