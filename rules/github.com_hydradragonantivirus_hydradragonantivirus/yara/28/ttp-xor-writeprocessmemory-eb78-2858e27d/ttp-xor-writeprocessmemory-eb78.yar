rule TTP_XOR_WriteProcessMemory_eb78 {
  strings:
    $key_eb78 = { bc 0a [2] 8e 28 [2] 88 1d [2] a6 1d [2] 99 01 }

  condition:
    any of them
}