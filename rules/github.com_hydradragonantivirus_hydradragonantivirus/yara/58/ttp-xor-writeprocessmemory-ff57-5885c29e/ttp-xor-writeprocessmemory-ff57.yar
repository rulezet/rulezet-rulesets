rule TTP_XOR_WriteProcessMemory_ff57 {
  strings:
    $key_ff57 = { a8 25 [2] 9a 07 [2] 9c 32 [2] b2 32 [2] 8d 2e }

  condition:
    any of them
}