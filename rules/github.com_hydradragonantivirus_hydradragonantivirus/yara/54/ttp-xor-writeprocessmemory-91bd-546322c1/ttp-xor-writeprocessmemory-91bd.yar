rule TTP_XOR_WriteProcessMemory_91bd {
  strings:
    $key_91bd = { c6 cf [2] f4 ed [2] f2 d8 [2] dc d8 [2] e3 c4 }

  condition:
    any of them
}