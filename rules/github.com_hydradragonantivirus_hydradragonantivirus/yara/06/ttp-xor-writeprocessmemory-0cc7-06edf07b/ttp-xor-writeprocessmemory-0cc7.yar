rule TTP_XOR_WriteProcessMemory_0cc7 {
  strings:
    $key_0cc7 = { 5b b5 [2] 69 97 [2] 6f a2 [2] 41 a2 [2] 7e be }

  condition:
    any of them
}