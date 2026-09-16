rule TTP_XOR_WriteProcessMemory_ff32 {
  strings:
    $key_ff32 = { a8 40 [2] 9a 62 [2] 9c 57 [2] b2 57 [2] 8d 4b }

  condition:
    any of them
}