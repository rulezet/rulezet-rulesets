rule TTP_XOR_WriteProcessMemory_f9c0 {
  strings:
    $key_f9c0 = { ae b2 [2] 9c 90 [2] 9a a5 [2] b4 a5 [2] 8b b9 }

  condition:
    any of them
}