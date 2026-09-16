rule TTP_XOR_WriteProcessMemory_8192 {
  strings:
    $key_8192 = { d6 e0 [2] e4 c2 [2] e2 f7 [2] cc f7 [2] f3 eb }

  condition:
    any of them
}