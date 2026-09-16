rule TTP_XOR_WriteProcessMemory_eb0e {
  strings:
    $key_eb0e = { bc 7c [2] 8e 5e [2] 88 6b [2] a6 6b [2] 99 77 }

  condition:
    any of them
}