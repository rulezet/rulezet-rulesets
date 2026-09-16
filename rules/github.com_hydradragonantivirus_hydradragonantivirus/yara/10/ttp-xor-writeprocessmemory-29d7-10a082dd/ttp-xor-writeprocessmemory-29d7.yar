rule TTP_XOR_WriteProcessMemory_29d7 {
  strings:
    $key_29d7 = { 7e a5 [2] 4c 87 [2] 4a b2 [2] 64 b2 [2] 5b ae }

  condition:
    any of them
}