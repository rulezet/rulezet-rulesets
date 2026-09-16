rule TTP_XOR_WriteProcessMemory_ff44 {
  strings:
    $key_ff44 = { a8 36 [2] 9a 14 [2] 9c 21 [2] b2 21 [2] 8d 3d }

  condition:
    any of them
}