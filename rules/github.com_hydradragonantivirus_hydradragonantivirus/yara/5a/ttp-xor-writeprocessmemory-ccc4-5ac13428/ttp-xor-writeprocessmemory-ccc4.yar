rule TTP_XOR_WriteProcessMemory_ccc4 {
  strings:
    $key_ccc4 = { 9b b6 [2] a9 94 [2] af a1 [2] 81 a1 [2] be bd }

  condition:
    any of them
}