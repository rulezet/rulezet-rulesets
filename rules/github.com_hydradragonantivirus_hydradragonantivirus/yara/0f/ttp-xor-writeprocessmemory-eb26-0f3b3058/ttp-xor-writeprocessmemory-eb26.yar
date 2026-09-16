rule TTP_XOR_WriteProcessMemory_eb26 {
  strings:
    $key_eb26 = { bc 54 [2] 8e 76 [2] 88 43 [2] a6 43 [2] 99 5f }

  condition:
    any of them
}