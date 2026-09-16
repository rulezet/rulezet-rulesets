rule TTP_XOR_WriteProcessMemory_4696 {
  strings:
    $key_4696 = { 11 e4 [2] 23 c6 [2] 25 f3 [2] 0b f3 [2] 34 ef }

  condition:
    any of them
}