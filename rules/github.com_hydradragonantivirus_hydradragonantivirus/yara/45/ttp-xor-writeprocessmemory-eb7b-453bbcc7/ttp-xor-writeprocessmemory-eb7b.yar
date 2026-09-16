rule TTP_XOR_WriteProcessMemory_eb7b {
  strings:
    $key_eb7b = { bc 09 [2] 8e 2b [2] 88 1e [2] a6 1e [2] 99 02 }

  condition:
    any of them
}