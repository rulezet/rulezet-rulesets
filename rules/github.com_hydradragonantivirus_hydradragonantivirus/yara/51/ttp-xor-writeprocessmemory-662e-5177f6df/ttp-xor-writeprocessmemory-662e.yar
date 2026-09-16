rule TTP_XOR_WriteProcessMemory_662e {
  strings:
    $key_662e = { 31 5c [2] 03 7e [2] 05 4b [2] 2b 4b [2] 14 57 }

  condition:
    any of them
}