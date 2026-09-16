rule TTP_XOR_WriteProcessMemory_bbbd {
  strings:
    $key_bbbd = { ec cf [2] de ed [2] d8 d8 [2] f6 d8 [2] c9 c4 }

  condition:
    any of them
}