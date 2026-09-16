rule TTP_XOR_WriteProcessMemory_f9c2 {
  strings:
    $key_f9c2 = { ae b0 [2] 9c 92 [2] 9a a7 [2] b4 a7 [2] 8b bb }

  condition:
    any of them
}