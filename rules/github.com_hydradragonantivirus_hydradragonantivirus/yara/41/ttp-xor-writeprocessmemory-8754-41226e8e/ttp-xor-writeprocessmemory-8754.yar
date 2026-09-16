rule TTP_XOR_WriteProcessMemory_8754 {
  strings:
    $key_8754 = { d0 26 [2] e2 04 [2] e4 31 [2] ca 31 [2] f5 2d }

  condition:
    any of them
}