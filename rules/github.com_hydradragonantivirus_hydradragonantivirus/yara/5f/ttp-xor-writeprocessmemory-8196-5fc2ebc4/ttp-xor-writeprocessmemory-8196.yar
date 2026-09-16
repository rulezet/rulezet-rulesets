rule TTP_XOR_WriteProcessMemory_8196 {
  strings:
    $key_8196 = { d6 e4 [2] e4 c6 [2] e2 f3 [2] cc f3 [2] f3 ef }

  condition:
    any of them
}