rule TTP_XOR_WriteProcessMemory_eb46 {
  strings:
    $key_eb46 = { bc 34 [2] 8e 16 [2] 88 23 [2] a6 23 [2] 99 3f }

  condition:
    any of them
}