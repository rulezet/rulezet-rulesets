rule TTP_XOR_WriteProcessMemory_8193 {
  strings:
    $key_8193 = { d6 e1 [2] e4 c3 [2] e2 f6 [2] cc f6 [2] f3 ea }

  condition:
    any of them
}