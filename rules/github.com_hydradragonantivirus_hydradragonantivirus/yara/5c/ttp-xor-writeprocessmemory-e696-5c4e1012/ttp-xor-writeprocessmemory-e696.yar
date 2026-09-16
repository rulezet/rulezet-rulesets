rule TTP_XOR_WriteProcessMemory_e696 {
  strings:
    $key_e696 = { b1 e4 [2] 83 c6 [2] 85 f3 [2] ab f3 [2] 94 ef }

  condition:
    any of them
}