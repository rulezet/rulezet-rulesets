rule TTP_XOR_WriteProcessMemory_85ee {
  strings:
    $key_85ee = { d2 9c [2] e0 be [2] e6 8b [2] c8 8b [2] f7 97 }

  condition:
    any of them
}