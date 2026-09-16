rule TTP_XOR_WriteProcessMemory_ff43 {
  strings:
    $key_ff43 = { a8 31 [2] 9a 13 [2] 9c 26 [2] b2 26 [2] 8d 3a }

  condition:
    any of them
}