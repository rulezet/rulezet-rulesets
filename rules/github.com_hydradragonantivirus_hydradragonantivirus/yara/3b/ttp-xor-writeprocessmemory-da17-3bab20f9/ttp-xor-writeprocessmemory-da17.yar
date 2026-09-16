rule TTP_XOR_WriteProcessMemory_da17 {
  strings:
    $key_da17 = { 8d 65 [2] bf 47 [2] b9 72 [2] 97 72 [2] a8 6e }

  condition:
    any of them
}