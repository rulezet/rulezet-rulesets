rule TTP_XOR_WriteProcessMemory_09d7 {
  strings:
    $key_09d7 = { 5e a5 [2] 6c 87 [2] 6a b2 [2] 44 b2 [2] 7b ae }

  condition:
    any of them
}