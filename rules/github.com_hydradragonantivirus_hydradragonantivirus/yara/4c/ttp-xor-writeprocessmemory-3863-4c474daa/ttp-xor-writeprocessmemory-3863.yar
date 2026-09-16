rule TTP_XOR_WriteProcessMemory_3863 {
  strings:
    $key_3863 = { 6f 11 [2] 5d 33 [2] 5b 06 [2] 75 06 [2] 4a 1a }

  condition:
    any of them
}