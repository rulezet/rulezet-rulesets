rule TTP_XOR_WriteProcessMemory_2b96 {
  strings:
    $key_2b96 = { 7c e4 [2] 4e c6 [2] 48 f3 [2] 66 f3 [2] 59 ef }

  condition:
    any of them
}