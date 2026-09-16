rule TTP_XOR_WriteProcessMemory_db9c {
  strings:
    $key_db9c = { 8c ee [2] be cc [2] b8 f9 [2] 96 f9 [2] a9 e5 }

  condition:
    any of them
}