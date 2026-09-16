rule TTP_XOR_WriteProcessMemory_e422 {
  strings:
    $key_e422 = { b3 50 [2] 81 72 [2] 87 47 [2] a9 47 [2] 96 5b }

  condition:
    any of them
}