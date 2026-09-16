rule TTP_XOR_WriteProcessMemory_eb65 {
  strings:
    $key_eb65 = { bc 17 [2] 8e 35 [2] 88 00 [2] a6 00 [2] 99 1c }

  condition:
    any of them
}