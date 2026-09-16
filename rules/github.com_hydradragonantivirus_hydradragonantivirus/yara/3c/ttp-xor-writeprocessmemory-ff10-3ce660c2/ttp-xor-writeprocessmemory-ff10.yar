rule TTP_XOR_WriteProcessMemory_ff10 {
  strings:
    $key_ff10 = { a8 62 [2] 9a 40 [2] 9c 75 [2] b2 75 [2] 8d 69 }

  condition:
    any of them
}