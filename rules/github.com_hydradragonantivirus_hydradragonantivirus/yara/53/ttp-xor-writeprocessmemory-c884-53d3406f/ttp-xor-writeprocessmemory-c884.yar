rule TTP_XOR_WriteProcessMemory_c884 {
  strings:
    $key_c884 = { 9f f6 [2] ad d4 [2] ab e1 [2] 85 e1 [2] ba fd }

  condition:
    any of them
}