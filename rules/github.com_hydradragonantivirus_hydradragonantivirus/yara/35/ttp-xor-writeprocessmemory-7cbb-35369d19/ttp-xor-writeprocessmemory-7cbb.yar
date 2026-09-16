rule TTP_XOR_WriteProcessMemory_7cbb {
  strings:
    $key_7cbb = { 2b c9 [2] 19 eb [2] 1f de [2] 31 de [2] 0e c2 }

  condition:
    any of them
}