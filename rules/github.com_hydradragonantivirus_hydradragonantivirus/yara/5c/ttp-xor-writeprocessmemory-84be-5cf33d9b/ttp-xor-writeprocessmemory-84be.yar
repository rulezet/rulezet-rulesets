rule TTP_XOR_WriteProcessMemory_84be {
  strings:
    $key_84be = { d3 cc [2] e1 ee [2] e7 db [2] c9 db [2] f6 c7 }

  condition:
    any of them
}