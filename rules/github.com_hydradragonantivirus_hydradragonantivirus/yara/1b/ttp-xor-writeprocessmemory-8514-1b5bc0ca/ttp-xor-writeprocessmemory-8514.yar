rule TTP_XOR_WriteProcessMemory_8514 {
  strings:
    $key_8514 = { d2 66 [2] e0 44 [2] e6 71 [2] c8 71 [2] f7 6d }

  condition:
    any of them
}