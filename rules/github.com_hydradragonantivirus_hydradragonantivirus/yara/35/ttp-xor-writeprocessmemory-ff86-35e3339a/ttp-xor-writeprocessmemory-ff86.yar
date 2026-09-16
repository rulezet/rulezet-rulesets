rule TTP_XOR_WriteProcessMemory_ff86 {
  strings:
    $key_ff86 = { a8 f4 [2] 9a d6 [2] 9c e3 [2] b2 e3 [2] 8d ff }

  condition:
    any of them
}