rule TTP_XOR_WriteProcessMemory_eb17 {
  strings:
    $key_eb17 = { bc 65 [2] 8e 47 [2] 88 72 [2] a6 72 [2] 99 6e }

  condition:
    any of them
}