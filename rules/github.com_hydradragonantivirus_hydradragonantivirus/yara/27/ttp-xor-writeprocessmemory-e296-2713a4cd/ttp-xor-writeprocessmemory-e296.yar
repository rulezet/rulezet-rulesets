rule TTP_XOR_WriteProcessMemory_e296 {
  strings:
    $key_e296 = { b5 e4 [2] 87 c6 [2] 81 f3 [2] af f3 [2] 90 ef }

  condition:
    any of them
}