rule TTP_XOR_WriteProcessMemory_2cc7 {
  strings:
    $key_2cc7 = { 7b b5 [2] 49 97 [2] 4f a2 [2] 61 a2 [2] 5e be }

  condition:
    any of them
}