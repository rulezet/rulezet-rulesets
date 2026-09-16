rule TTP_XOR_WriteProcessMemory_eb72 {
  strings:
    $key_eb72 = { bc 00 [2] 8e 22 [2] 88 17 [2] a6 17 [2] 99 0b }

  condition:
    any of them
}