rule TTP_XOR_WriteProcessMemory_59ce {
  strings:
    $key_59ce = { 0e bc [2] 3c 9e [2] 3a ab [2] 14 ab [2] 2b b7 }

  condition:
    any of them
}