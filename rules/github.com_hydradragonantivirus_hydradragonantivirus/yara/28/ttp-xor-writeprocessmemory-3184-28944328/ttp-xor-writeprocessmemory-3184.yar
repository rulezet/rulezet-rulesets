rule TTP_XOR_WriteProcessMemory_3184 {
  strings:
    $key_3184 = { 66 f6 [2] 54 d4 [2] 52 e1 [2] 7c e1 [2] 43 fd }

  condition:
    any of them
}