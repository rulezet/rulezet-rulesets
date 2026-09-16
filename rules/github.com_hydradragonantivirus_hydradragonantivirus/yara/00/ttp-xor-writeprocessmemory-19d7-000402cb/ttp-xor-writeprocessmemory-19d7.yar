rule TTP_XOR_WriteProcessMemory_19d7 {
  strings:
    $key_19d7 = { 4e a5 [2] 7c 87 [2] 7a b2 [2] 54 b2 [2] 6b ae }

  condition:
    any of them
}