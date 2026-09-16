rule TTP_XOR_WriteProcessMemory_e432 {
  strings:
    $key_e432 = { b3 40 [2] 81 62 [2] 87 57 [2] a9 57 [2] 96 4b }

  condition:
    any of them
}