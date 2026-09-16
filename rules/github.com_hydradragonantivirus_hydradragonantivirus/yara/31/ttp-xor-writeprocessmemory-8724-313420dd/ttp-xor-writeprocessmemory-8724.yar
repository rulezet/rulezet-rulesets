rule TTP_XOR_WriteProcessMemory_8724 {
  strings:
    $key_8724 = { d0 56 [2] e2 74 [2] e4 41 [2] ca 41 [2] f5 5d }

  condition:
    any of them
}