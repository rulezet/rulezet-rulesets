rule TTP_XOR_WriteProcessMemory_3dbd {
  strings:
    $key_3dbd = { 6a cf [2] 58 ed [2] 5e d8 [2] 70 d8 [2] 4f c4 }

  condition:
    any of them
}