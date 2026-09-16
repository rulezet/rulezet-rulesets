rule TTP_XOR_WriteProcessMemory_e460 {
  strings:
    $key_e460 = { b3 12 [2] 81 30 [2] 87 05 [2] a9 05 [2] 96 19 }

  condition:
    any of them
}