rule TTP_XOR_WriteProcessMemory_ee84 {
  strings:
    $key_ee84 = { b9 f6 [2] 8b d4 [2] 8d e1 [2] a3 e1 [2] 9c fd }

  condition:
    any of them
}