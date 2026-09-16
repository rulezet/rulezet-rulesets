rule TTP_XOR_WriteProcessMemory_431e {
  strings:
    $key_431e = { 14 6c [2] 26 4e [2] 20 7b [2] 0e 7b [2] 31 67 }

  condition:
    any of them
}