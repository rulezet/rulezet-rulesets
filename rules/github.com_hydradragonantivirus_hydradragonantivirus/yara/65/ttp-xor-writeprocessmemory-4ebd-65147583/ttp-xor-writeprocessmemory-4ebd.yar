rule TTP_XOR_WriteProcessMemory_4ebd {
  strings:
    $key_4ebd = { 19 cf [2] 2b ed [2] 2d d8 [2] 03 d8 [2] 3c c4 }

  condition:
    any of them
}