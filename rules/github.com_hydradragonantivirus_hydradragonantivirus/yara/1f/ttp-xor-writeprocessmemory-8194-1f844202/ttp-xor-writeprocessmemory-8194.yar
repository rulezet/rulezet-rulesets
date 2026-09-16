rule TTP_XOR_WriteProcessMemory_8194 {
  strings:
    $key_8194 = { d6 e6 [2] e4 c4 [2] e2 f1 [2] cc f1 [2] f3 ed }

  condition:
    any of them
}