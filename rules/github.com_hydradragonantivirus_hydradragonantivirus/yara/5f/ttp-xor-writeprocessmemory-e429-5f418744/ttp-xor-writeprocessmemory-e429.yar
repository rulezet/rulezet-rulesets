rule TTP_XOR_WriteProcessMemory_e429 {
  strings:
    $key_e429 = { b3 5b [2] 81 79 [2] 87 4c [2] a9 4c [2] 96 50 }

  condition:
    any of them
}