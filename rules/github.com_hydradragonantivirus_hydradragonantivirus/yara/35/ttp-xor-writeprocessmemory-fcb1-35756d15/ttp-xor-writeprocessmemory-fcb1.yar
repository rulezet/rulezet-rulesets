rule TTP_XOR_WriteProcessMemory_fcb1 {
  strings:
    $key_fcb1 = { ab c3 [2] 99 e1 [2] 9f d4 [2] b1 d4 [2] 8e c8 }

  condition:
    any of them
}