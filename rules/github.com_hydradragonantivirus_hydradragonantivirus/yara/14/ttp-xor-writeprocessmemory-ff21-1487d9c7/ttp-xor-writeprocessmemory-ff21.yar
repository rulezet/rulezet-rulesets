rule TTP_XOR_WriteProcessMemory_ff21 {
  strings:
    $key_ff21 = { a8 53 [2] 9a 71 [2] 9c 44 [2] b2 44 [2] 8d 58 }

  condition:
    any of them
}