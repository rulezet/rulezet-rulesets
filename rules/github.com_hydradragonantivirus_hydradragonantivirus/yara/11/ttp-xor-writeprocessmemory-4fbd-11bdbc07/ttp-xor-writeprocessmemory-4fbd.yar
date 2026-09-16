rule TTP_XOR_WriteProcessMemory_4fbd {
  strings:
    $key_4fbd = { 18 cf [2] 2a ed [2] 2c d8 [2] 02 d8 [2] 3d c4 }

  condition:
    any of them
}