rule TTP_XOR_WriteProcessMemory_f9b0 {
  strings:
    $key_f9b0 = { ae c2 [2] 9c e0 [2] 9a d5 [2] b4 d5 [2] 8b c9 }

  condition:
    any of them
}