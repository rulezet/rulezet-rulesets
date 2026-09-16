rule TTP_XOR_WriteProcessMemory_eb87 {
  strings:
    $key_eb87 = { bc f5 [2] 8e d7 [2] 88 e2 [2] a6 e2 [2] 99 fe }

  condition:
    any of them
}