rule TTP_XOR_WriteProcessMemory_8785 {
  strings:
    $key_8785 = { d0 f7 [2] e2 d5 [2] e4 e0 [2] ca e0 [2] f5 fc }

  condition:
    any of them
}