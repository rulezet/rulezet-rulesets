rule TTP_XOR_WriteProcessMemory_774c {
  strings:
    $key_774c = { 20 3e [2] 12 1c [2] 14 29 [2] 3a 29 [2] 05 35 }

  condition:
    any of them
}