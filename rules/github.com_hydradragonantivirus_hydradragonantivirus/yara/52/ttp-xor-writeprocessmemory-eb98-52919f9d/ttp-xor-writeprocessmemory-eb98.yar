rule TTP_XOR_WriteProcessMemory_eb98 {
  strings:
    $key_eb98 = { bc ea [2] 8e c8 [2] 88 fd [2] a6 fd [2] 99 e1 }

  condition:
    any of them
}