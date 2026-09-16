rule TTP_XOR_WriteProcessMemory_e477 {
  strings:
    $key_e477 = { b3 05 [2] 81 27 [2] 87 12 [2] a9 12 [2] 96 0e }

  condition:
    any of them
}