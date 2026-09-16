rule TTP_XOR_WriteProcessMemory_6fbd {
  strings:
    $key_6fbd = { 38 cf [2] 0a ed [2] 0c d8 [2] 22 d8 [2] 1d c4 }

  condition:
    any of them
}