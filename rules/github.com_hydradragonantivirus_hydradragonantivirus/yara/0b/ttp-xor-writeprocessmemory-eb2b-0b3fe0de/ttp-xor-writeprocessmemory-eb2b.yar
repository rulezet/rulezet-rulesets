rule TTP_XOR_WriteProcessMemory_eb2b {
  strings:
    $key_eb2b = { bc 59 [2] 8e 7b [2] 88 4e [2] a6 4e [2] 99 52 }

  condition:
    any of them
}