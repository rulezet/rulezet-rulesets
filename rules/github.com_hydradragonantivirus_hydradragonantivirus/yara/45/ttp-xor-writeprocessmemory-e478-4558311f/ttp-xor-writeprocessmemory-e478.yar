rule TTP_XOR_WriteProcessMemory_e478 {
  strings:
    $key_e478 = { b3 0a [2] 81 28 [2] 87 1d [2] a9 1d [2] 96 01 }

  condition:
    any of them
}