rule TTP_XOR_WriteProcessMemory_8114 {
  strings:
    $key_8114 = { d6 66 [2] e4 44 [2] e2 71 [2] cc 71 [2] f3 6d }

  condition:
    any of them
}