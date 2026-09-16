rule TTP_XOR_WriteProcessMemory_022e {
  strings:
    $key_022e = { 55 5c [2] 67 7e [2] 61 4b [2] 4f 4b [2] 70 57 }

  condition:
    any of them
}