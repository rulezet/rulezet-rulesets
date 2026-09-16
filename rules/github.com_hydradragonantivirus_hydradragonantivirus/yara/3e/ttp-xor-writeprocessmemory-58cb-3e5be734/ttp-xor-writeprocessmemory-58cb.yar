rule TTP_XOR_WriteProcessMemory_58cb {
  strings:
    $key_58cb = { 0f b9 [2] 3d 9b [2] 3b ae [2] 15 ae [2] 2a b2 }

  condition:
    any of them
}