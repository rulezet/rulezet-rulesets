rule TTP_XOR_WriteProcessMemory_8185 {
  strings:
    $key_8185 = { d6 f7 [2] e4 d5 [2] e2 e0 [2] cc e0 [2] f3 fc }

  condition:
    any of them
}