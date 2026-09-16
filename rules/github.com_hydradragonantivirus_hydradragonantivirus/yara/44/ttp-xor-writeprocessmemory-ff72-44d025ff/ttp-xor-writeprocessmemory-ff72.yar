rule TTP_XOR_WriteProcessMemory_ff72 {
  strings:
    $key_ff72 = { a8 00 [2] 9a 22 [2] 9c 17 [2] b2 17 [2] 8d 0b }

  condition:
    any of them
}