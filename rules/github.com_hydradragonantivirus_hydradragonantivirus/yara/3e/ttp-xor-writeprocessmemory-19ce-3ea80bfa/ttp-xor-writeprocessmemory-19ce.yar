rule TTP_XOR_WriteProcessMemory_19ce {
  strings:
    $key_19ce = { 4e bc [2] 7c 9e [2] 7a ab [2] 54 ab [2] 6b b7 }

  condition:
    any of them
}