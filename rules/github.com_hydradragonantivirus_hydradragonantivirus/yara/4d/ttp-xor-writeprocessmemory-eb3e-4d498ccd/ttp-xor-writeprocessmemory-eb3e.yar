rule TTP_XOR_WriteProcessMemory_eb3e {
  strings:
    $key_eb3e = { bc 4c [2] 8e 6e [2] 88 5b [2] a6 5b [2] 99 47 }

  condition:
    any of them
}