rule TTP_XOR_WriteProcessMemory_8717 {
  strings:
    $key_8717 = { d0 65 [2] e2 47 [2] e4 72 [2] ca 72 [2] f5 6e }

  condition:
    any of them
}