rule TTP_XOR_WriteProcessMemory_ff41 {
  strings:
    $key_ff41 = { a8 33 [2] 9a 11 [2] 9c 24 [2] b2 24 [2] 8d 38 }

  condition:
    any of them
}