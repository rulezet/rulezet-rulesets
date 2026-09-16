rule TTP_XOR_WriteProcessMemory_ff08 {
  strings:
    $key_ff08 = { a8 7a [2] 9a 58 [2] 9c 6d [2] b2 6d [2] 8d 71 }

  condition:
    any of them
}