rule TTP_XOR_WriteProcessMemory_ff33 {
  strings:
    $key_ff33 = { a8 41 [2] 9a 63 [2] 9c 56 [2] b2 56 [2] 8d 4a }

  condition:
    any of them
}