rule TTP_XOR_WriteProcessMemory_ebd1 {
  strings:
    $key_ebd1 = { bc a3 [2] 8e 81 [2] 88 b4 [2] a6 b4 [2] 99 a8 }

  condition:
    any of them
}