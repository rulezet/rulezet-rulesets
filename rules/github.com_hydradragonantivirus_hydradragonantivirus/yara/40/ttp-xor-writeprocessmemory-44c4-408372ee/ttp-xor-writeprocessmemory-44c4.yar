rule TTP_XOR_WriteProcessMemory_44c4 {
  strings:
    $key_44c4 = { 13 b6 [2] 21 94 [2] 27 a1 [2] 09 a1 [2] 36 bd }

  condition:
    any of them
}