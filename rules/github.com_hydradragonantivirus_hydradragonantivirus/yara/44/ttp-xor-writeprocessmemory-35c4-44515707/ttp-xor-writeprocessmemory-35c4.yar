rule TTP_XOR_WriteProcessMemory_35c4 {
  strings:
    $key_35c4 = { 62 b6 [2] 50 94 [2] 56 a1 [2] 78 a1 [2] 47 bd }

  condition:
    any of them
}