rule TTP_XOR_WriteProcessMemory_4686 {
  strings:
    $key_4686 = { 11 f4 [2] 23 d6 [2] 25 e3 [2] 0b e3 [2] 34 ff }

  condition:
    any of them
}