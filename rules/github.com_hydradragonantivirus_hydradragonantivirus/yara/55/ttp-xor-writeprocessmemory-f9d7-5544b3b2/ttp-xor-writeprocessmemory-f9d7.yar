rule TTP_XOR_WriteProcessMemory_f9d7 {
  strings:
    $key_f9d7 = { ae a5 [2] 9c 87 [2] 9a b2 [2] b4 b2 [2] 8b ae }

  condition:
    any of them
}