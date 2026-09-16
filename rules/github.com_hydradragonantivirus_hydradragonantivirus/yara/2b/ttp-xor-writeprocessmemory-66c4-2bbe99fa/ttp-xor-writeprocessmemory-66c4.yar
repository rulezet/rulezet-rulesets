rule TTP_XOR_WriteProcessMemory_66c4 {
  strings:
    $key_66c4 = { 31 b6 [2] 03 94 [2] 05 a1 [2] 2b a1 [2] 14 bd }

  condition:
    any of them
}