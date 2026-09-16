rule TTP_XOR_WriteProcessMemory_f9c1 {
  strings:
    $key_f9c1 = { ae b3 [2] 9c 91 [2] 9a a4 [2] b4 a4 [2] 8b b8 }

  condition:
    any of them
}