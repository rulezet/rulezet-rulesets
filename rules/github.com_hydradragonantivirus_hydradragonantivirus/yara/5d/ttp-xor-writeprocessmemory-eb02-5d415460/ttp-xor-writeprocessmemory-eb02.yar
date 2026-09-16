rule TTP_XOR_WriteProcessMemory_eb02 {
  strings:
    $key_eb02 = { bc 70 [2] 8e 52 [2] 88 67 [2] a6 67 [2] 99 7b }

  condition:
    any of them
}