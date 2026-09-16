rule TTP_XOR_WriteProcessMemory_87be {
  strings:
    $key_87be = { d0 cc [2] e2 ee [2] e4 db [2] ca db [2] f5 c7 }

  condition:
    any of them
}