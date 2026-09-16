rule TTP_XOR_WriteProcessMemory_fcb4 {
  strings:
    $key_fcb4 = { ab c6 [2] 99 e4 [2] 9f d1 [2] b1 d1 [2] 8e cd }

  condition:
    any of them
}