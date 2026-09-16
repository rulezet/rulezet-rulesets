rule TTP_XOR_WriteProcessMemory_d496 {
  strings:
    $key_d496 = { 83 e4 [2] b1 c6 [2] b7 f3 [2] 99 f3 [2] a6 ef }

  condition:
    any of them
}