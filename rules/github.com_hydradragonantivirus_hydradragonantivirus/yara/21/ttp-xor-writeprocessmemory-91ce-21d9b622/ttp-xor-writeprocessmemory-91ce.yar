rule TTP_XOR_WriteProcessMemory_91ce {
  strings:
    $key_91ce = { c6 bc [2] f4 9e [2] f2 ab [2] dc ab [2] e3 b7 }

  condition:
    any of them
}