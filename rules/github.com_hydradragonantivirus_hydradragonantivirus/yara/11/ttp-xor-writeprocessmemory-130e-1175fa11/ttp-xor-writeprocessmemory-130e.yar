rule TTP_XOR_WriteProcessMemory_130e {
  strings:
    $key_130e = { 44 7c [2] 76 5e [2] 70 6b [2] 5e 6b [2] 61 77 }

  condition:
    any of them
}