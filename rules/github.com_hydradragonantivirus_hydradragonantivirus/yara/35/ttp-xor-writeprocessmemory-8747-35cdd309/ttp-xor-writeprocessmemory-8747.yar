rule TTP_XOR_WriteProcessMemory_8747 {
  strings:
    $key_8747 = { d0 35 [2] e2 17 [2] e4 22 [2] ca 22 [2] f5 3e }

  condition:
    any of them
}