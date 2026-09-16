rule TTP_XOR_WriteProcessMemory_eb41 {
  strings:
    $key_eb41 = { bc 33 [2] 8e 11 [2] 88 24 [2] a6 24 [2] 99 38 }

  condition:
    any of them
}