rule TTP_XOR_WriteProcessMemory_e43d {
  strings:
    $key_e43d = { b3 4f [2] 81 6d [2] 87 58 [2] a9 58 [2] 96 44 }

  condition:
    any of them
}