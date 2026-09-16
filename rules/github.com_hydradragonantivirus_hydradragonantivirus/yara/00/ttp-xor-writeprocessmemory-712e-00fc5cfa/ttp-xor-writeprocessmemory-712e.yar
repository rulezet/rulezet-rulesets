rule TTP_XOR_WriteProcessMemory_712e {
  strings:
    $key_712e = { 26 5c [2] 14 7e [2] 12 4b [2] 3c 4b [2] 03 57 }

  condition:
    any of them
}