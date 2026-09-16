rule TTP_XOR_WriteProcessMemory_eb64 {
  strings:
    $key_eb64 = { bc 16 [2] 8e 34 [2] 88 01 [2] a6 01 [2] 99 1d }

  condition:
    any of them
}