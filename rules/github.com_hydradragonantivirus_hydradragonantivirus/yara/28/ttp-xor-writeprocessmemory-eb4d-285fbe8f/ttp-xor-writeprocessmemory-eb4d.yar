rule TTP_XOR_WriteProcessMemory_eb4d {
  strings:
    $key_eb4d = { bc 3f [2] 8e 1d [2] 88 28 [2] a6 28 [2] 99 34 }

  condition:
    any of them
}