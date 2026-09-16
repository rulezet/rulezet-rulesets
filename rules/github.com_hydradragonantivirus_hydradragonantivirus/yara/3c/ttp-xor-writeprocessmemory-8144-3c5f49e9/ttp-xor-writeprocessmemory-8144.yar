rule TTP_XOR_WriteProcessMemory_8144 {
  strings:
    $key_8144 = { d6 36 [2] e4 14 [2] e2 21 [2] cc 21 [2] f3 3d }

  condition:
    any of them
}