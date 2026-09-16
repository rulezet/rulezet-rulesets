rule TTP_XOR_WriteProcessMemory_eb5d {
  strings:
    $key_eb5d = { bc 2f [2] 8e 0d [2] 88 38 [2] a6 38 [2] 99 24 }

  condition:
    any of them
}