rule TTP_XOR_WriteProcessMemory_4813 {
  strings:
    $key_4813 = { 1f 61 [2] 2d 43 [2] 2b 76 [2] 05 76 [2] 3a 6a }

  condition:
    any of them
}