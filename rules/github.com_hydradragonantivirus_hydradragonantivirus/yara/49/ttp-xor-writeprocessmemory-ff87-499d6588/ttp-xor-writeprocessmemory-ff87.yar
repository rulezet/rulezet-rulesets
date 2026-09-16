rule TTP_XOR_WriteProcessMemory_ff87 {
  strings:
    $key_ff87 = { a8 f5 [2] 9a d7 [2] 9c e2 [2] b2 e2 [2] 8d fe }

  condition:
    any of them
}