rule TTP_XOR_WriteProcessMemory_e494 {
  strings:
    $key_e494 = { b3 e6 [2] 81 c4 [2] 87 f1 [2] a9 f1 [2] 96 ed }

  condition:
    any of them
}