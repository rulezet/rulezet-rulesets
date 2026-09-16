rule TTP_XOR_WriteProcessMemory_ff66 {
  strings:
    $key_ff66 = { a8 14 [2] 9a 36 [2] 9c 03 [2] b2 03 [2] 8d 1f }

  condition:
    any of them
}