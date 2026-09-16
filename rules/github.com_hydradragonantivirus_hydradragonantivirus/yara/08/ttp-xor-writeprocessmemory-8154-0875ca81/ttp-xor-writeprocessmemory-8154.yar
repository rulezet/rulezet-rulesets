rule TTP_XOR_WriteProcessMemory_8154 {
  strings:
    $key_8154 = { d6 26 [2] e4 04 [2] e2 31 [2] cc 31 [2] f3 2d }

  condition:
    any of them
}