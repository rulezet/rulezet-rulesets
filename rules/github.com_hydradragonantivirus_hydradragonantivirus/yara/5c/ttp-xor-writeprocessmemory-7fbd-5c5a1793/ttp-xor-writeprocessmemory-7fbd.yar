rule TTP_XOR_WriteProcessMemory_7fbd {
  strings:
    $key_7fbd = { 28 cf [2] 1a ed [2] 1c d8 [2] 32 d8 [2] 0d c4 }

  condition:
    any of them
}