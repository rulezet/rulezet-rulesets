rule TTP_XOR_WriteProcessMemory_ccbb {
  strings:
    $key_ccbb = { 9b c9 [2] a9 eb [2] af de [2] 81 de [2] be c2 }

  condition:
    any of them
}