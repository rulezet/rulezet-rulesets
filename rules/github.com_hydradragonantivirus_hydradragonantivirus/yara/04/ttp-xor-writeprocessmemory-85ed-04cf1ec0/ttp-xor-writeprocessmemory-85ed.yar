rule TTP_XOR_WriteProcessMemory_85ed {
  strings:
    $key_85ed = { d2 9f [2] e0 bd [2] e6 88 [2] c8 88 [2] f7 94 }

  condition:
    any of them
}