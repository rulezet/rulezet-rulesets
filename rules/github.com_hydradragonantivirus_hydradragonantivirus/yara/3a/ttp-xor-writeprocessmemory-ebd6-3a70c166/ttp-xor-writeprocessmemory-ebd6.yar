rule TTP_XOR_WriteProcessMemory_ebd6 {
  strings:
    $key_ebd6 = { bc a4 [2] 8e 86 [2] 88 b3 [2] a6 b3 [2] 99 af }

  condition:
    any of them
}