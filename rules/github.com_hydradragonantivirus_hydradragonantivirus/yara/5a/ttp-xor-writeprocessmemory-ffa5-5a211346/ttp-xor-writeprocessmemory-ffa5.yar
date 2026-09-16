rule TTP_XOR_WriteProcessMemory_ffa5 {
  strings:
    $key_ffa5 = { a8 d7 [2] 9a f5 [2] 9c c0 [2] b2 c0 [2] 8d dc }

  condition:
    any of them
}