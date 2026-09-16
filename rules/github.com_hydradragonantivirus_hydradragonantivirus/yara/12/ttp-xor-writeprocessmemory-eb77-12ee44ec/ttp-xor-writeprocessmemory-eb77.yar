rule TTP_XOR_WriteProcessMemory_eb77 {
  strings:
    $key_eb77 = { bc 05 [2] 8e 27 [2] 88 12 [2] a6 12 [2] 99 0e }

  condition:
    any of them
}