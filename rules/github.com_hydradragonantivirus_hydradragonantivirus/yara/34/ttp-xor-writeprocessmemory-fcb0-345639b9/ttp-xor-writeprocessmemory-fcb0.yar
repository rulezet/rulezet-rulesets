rule TTP_XOR_WriteProcessMemory_fcb0 {
  strings:
    $key_fcb0 = { ab c2 [2] 99 e0 [2] 9f d5 [2] b1 d5 [2] 8e c9 }

  condition:
    any of them
}