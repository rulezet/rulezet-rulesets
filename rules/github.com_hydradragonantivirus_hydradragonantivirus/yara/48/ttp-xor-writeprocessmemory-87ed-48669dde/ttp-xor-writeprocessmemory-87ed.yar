rule TTP_XOR_WriteProcessMemory_87ed {
  strings:
    $key_87ed = { d0 9f [2] e2 bd [2] e4 88 [2] ca 88 [2] f5 94 }

  condition:
    any of them
}