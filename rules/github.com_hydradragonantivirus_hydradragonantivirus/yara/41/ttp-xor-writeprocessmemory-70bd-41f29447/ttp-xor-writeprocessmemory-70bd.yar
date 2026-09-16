rule TTP_XOR_WriteProcessMemory_70bd {
  strings:
    $key_70bd = { 27 cf [2] 15 ed [2] 13 d8 [2] 3d d8 [2] 02 c4 }

  condition:
    any of them
}