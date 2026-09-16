rule TTP_XOR_WriteProcessMemory_5cc7 {
  strings:
    $key_5cc7 = { 0b b5 [2] 39 97 [2] 3f a2 [2] 11 a2 [2] 2e be }

  condition:
    any of them
}