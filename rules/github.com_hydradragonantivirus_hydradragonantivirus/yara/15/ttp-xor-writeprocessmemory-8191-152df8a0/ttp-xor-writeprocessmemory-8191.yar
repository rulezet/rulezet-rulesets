rule TTP_XOR_WriteProcessMemory_8191 {
  strings:
    $key_8191 = { d6 e3 [2] e4 c1 [2] e2 f4 [2] cc f4 [2] f3 e8 }

  condition:
    any of them
}