rule TTP_XOR_WriteProcessMemory_eb45 {
  strings:
    $key_eb45 = { bc 37 [2] 8e 15 [2] 88 20 [2] a6 20 [2] 99 3c }

  condition:
    any of them
}