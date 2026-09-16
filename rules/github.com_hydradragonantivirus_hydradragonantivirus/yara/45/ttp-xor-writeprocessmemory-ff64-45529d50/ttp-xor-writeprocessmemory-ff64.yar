rule TTP_XOR_WriteProcessMemory_ff64 {
  strings:
    $key_ff64 = { a8 16 [2] 9a 34 [2] 9c 01 [2] b2 01 [2] 8d 1d }

  condition:
    any of them
}