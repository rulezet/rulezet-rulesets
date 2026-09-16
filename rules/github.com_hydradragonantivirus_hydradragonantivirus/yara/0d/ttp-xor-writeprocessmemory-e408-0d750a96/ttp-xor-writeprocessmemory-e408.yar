rule TTP_XOR_WriteProcessMemory_e408 {
  strings:
    $key_e408 = { b3 7a [2] 81 58 [2] 87 6d [2] a9 6d [2] 96 71 }

  condition:
    any of them
}