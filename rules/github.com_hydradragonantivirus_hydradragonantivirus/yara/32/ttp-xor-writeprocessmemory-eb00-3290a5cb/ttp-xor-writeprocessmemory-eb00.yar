rule TTP_XOR_WriteProcessMemory_eb00 {
  strings:
    $key_eb00 = { bc 72 [2] 8e 50 [2] 88 65 [2] a6 65 [2] 99 79 }

  condition:
    any of them
}