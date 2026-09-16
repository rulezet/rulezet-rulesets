rule TTP_XOR_WriteProcessMemory_eb48 {
  strings:
    $key_eb48 = { bc 3a [2] 8e 18 [2] 88 2d [2] a6 2d [2] 99 31 }

  condition:
    any of them
}