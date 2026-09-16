rule TTP_XOR_WriteProcessMemory_8fbd {
  strings:
    $key_8fbd = { d8 cf [2] ea ed [2] ec d8 [2] c2 d8 [2] fd c4 }

  condition:
    any of them
}