rule TTP_XOR_WriteProcessMemory_726c {
  strings:
    $key_726c = { 25 1e [2] 17 3c [2] 11 09 [2] 3f 09 [2] 00 15 }

  condition:
    any of them
}