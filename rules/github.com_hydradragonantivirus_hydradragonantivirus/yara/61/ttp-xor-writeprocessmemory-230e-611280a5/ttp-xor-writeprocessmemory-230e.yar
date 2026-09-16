rule TTP_XOR_WriteProcessMemory_230e {
  strings:
    $key_230e = { 74 7c [2] 46 5e [2] 40 6b [2] 6e 6b [2] 51 77 }

  condition:
    any of them
}