rule TTP_XOR_WriteProcessMemory_ecdd {
  strings:
    $key_ecdd = { bb af [2] 89 8d [2] 8f b8 [2] a1 b8 [2] 9e a4 }

  condition:
    any of them
}