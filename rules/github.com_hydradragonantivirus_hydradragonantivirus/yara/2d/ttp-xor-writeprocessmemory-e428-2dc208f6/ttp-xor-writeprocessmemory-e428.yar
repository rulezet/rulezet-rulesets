rule TTP_XOR_WriteProcessMemory_e428 {
  strings:
    $key_e428 = { b3 5a [2] 81 78 [2] 87 4d [2] a9 4d [2] 96 51 }

  condition:
    any of them
}