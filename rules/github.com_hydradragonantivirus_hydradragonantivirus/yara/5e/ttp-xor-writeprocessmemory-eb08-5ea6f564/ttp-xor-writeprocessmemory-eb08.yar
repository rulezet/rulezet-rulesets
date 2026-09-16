rule TTP_XOR_WriteProcessMemory_eb08 {
  strings:
    $key_eb08 = { bc 7a [2] 8e 58 [2] 88 6d [2] a6 6d [2] 99 71 }

  condition:
    any of them
}