rule TTP_XOR_WriteProcessMemory_eb1b {
  strings:
    $key_eb1b = { bc 69 [2] 8e 4b [2] 88 7e [2] a6 7e [2] 99 62 }

  condition:
    any of them
}