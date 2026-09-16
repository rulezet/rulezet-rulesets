rule TTP_XOR_WriteProcessMemory_ff63 {
  strings:
    $key_ff63 = { a8 11 [2] 9a 33 [2] 9c 06 [2] b2 06 [2] 8d 1a }

  condition:
    any of them
}