rule TTP_XOR_WriteProcessMemory_ff36 {
  strings:
    $key_ff36 = { a8 44 [2] 9a 66 [2] 9c 53 [2] b2 53 [2] 8d 4f }

  condition:
    any of them
}