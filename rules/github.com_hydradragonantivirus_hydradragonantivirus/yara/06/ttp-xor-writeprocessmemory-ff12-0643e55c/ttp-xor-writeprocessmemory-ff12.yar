rule TTP_XOR_WriteProcessMemory_ff12 {
  strings:
    $key_ff12 = { a8 60 [2] 9a 42 [2] 9c 77 [2] b2 77 [2] 8d 6b }

  condition:
    any of them
}