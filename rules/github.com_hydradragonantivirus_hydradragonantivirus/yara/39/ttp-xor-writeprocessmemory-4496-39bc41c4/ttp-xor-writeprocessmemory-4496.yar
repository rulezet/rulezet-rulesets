rule TTP_XOR_WriteProcessMemory_4496 {
  strings:
    $key_4496 = { 13 e4 [2] 21 c6 [2] 27 f3 [2] 09 f3 [2] 36 ef }

  condition:
    any of them
}