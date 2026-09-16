rule TTP_XOR_WriteProcessMemory_eb30 {
  strings:
    $key_eb30 = { bc 42 [2] 8e 60 [2] 88 55 [2] a6 55 [2] 99 49 }

  condition:
    any of them
}