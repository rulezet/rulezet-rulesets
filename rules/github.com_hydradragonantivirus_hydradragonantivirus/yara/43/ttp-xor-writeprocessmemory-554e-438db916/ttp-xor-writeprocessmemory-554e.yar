rule TTP_XOR_WriteProcessMemory_554e {
  strings:
    $key_554e = { 02 3c [2] 30 1e [2] 36 2b [2] 18 2b [2] 27 37 }

  condition:
    any of them
}