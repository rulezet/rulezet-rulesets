rule TTP_XOR_WriteProcessMemory_eb11 {
  strings:
    $key_eb11 = { bc 63 [2] 8e 41 [2] 88 74 [2] a6 74 [2] 99 68 }

  condition:
    any of them
}