rule TTP_XOR_WriteProcessMemory_6796 {
  strings:
    $key_6796 = { 30 e4 [2] 02 c6 [2] 04 f3 [2] 2a f3 [2] 15 ef }

  condition:
    any of them
}