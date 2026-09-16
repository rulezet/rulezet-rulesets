rule TTP_XOR_WriteProcessMemory_da24 {
  strings:
    $key_da24 = { 8d 56 [2] bf 74 [2] b9 41 [2] 97 41 [2] a8 5d }

  condition:
    any of them
}