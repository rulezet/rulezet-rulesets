rule TTP_XOR_WriteProcessMemory_0886 {
  strings:
    $key_0886 = { 5f f4 [2] 6d d6 [2] 6b e3 [2] 45 e3 [2] 7a ff }

  condition:
    any of them
}