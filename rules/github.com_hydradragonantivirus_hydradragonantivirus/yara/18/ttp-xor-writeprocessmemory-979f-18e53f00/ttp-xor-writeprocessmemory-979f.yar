rule TTP_XOR_WriteProcessMemory_979f {
  strings:
    $key_979f = { c0 ed [2] f2 cf [2] f4 fa [2] da fa [2] e5 e6 }

  condition:
    any of them
}