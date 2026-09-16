rule TTP_XOR_WriteProcessMemory_e479 {
  strings:
    $key_e479 = { b3 0b [2] 81 29 [2] 87 1c [2] a9 1c [2] 96 00 }

  condition:
    any of them
}