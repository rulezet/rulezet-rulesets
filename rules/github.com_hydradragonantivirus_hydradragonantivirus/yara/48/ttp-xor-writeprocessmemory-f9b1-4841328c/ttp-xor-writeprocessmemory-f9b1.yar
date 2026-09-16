rule TTP_XOR_WriteProcessMemory_f9b1 {
  strings:
    $key_f9b1 = { ae c3 [2] 9c e1 [2] 9a d4 [2] b4 d4 [2] 8b c8 }

  condition:
    any of them
}