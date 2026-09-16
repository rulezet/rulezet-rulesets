rule TTP_XOR_WriteProcessMemory_84ee {
  strings:
    $key_84ee = { d3 9c [2] e1 be [2] e7 8b [2] c9 8b [2] f6 97 }

  condition:
    any of them
}