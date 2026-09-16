rule TTP_XOR_WriteProcessMemory_451e {
  strings:
    $key_451e = { 12 6c [2] 20 4e [2] 26 7b [2] 08 7b [2] 37 67 }

  condition:
    any of them
}