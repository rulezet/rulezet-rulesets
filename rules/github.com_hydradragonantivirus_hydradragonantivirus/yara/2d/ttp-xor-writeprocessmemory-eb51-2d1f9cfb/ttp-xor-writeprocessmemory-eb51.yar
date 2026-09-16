rule TTP_XOR_WriteProcessMemory_eb51 {
  strings:
    $key_eb51 = { bc 23 [2] 8e 01 [2] 88 34 [2] a6 34 [2] 99 28 }

  condition:
    any of them
}