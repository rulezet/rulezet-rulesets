rule TTP_XOR_WriteProcessMemory_1dbd {
  strings:
    $key_1dbd = { 4a cf [2] 78 ed [2] 7e d8 [2] 50 d8 [2] 6f c4 }

  condition:
    any of them
}