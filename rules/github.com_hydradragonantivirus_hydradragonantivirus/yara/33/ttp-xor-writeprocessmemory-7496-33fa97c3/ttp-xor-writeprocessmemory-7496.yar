rule TTP_XOR_WriteProcessMemory_7496 {
  strings:
    $key_7496 = { 23 e4 [2] 11 c6 [2] 17 f3 [2] 39 f3 [2] 06 ef }

  condition:
    any of them
}