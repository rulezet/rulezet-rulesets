rule TTP_XOR_WriteProcessMemory_ecfc {
  strings:
    $key_ecfc = { bb 8e [2] 89 ac [2] 8f 99 [2] a1 99 [2] 9e 85 }

  condition:
    any of them
}