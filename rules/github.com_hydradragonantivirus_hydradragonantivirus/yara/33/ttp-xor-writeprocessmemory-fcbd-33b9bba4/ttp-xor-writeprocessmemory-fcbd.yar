rule TTP_XOR_WriteProcessMemory_fcbd {
  strings:
    $key_fcbd = { ab cf [2] 99 ed [2] 9f d8 [2] b1 d8 [2] 8e c4 }

  condition:
    any of them
}