rule TTP_XOR_WriteProcessMemory_eb5b {
  strings:
    $key_eb5b = { bc 29 [2] 8e 0b [2] 88 3e [2] a6 3e [2] 99 22 }

  condition:
    any of them
}