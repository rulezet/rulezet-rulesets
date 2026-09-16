rule TTP_XOR_WriteProcessMemory_eb68 {
  strings:
    $key_eb68 = { bc 1a [2] 8e 38 [2] 88 0d [2] a6 0d [2] 99 11 }

  condition:
    any of them
}