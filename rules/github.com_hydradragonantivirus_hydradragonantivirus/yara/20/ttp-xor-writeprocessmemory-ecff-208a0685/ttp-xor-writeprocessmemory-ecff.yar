rule TTP_XOR_WriteProcessMemory_ecff {
  strings:
    $key_ecff = { bb 8d [2] 89 af [2] 8f 9a [2] a1 9a [2] 9e 86 }

  condition:
    any of them
}