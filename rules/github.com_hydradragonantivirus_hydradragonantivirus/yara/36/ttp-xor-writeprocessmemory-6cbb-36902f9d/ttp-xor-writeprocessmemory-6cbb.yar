rule TTP_XOR_WriteProcessMemory_6cbb {
  strings:
    $key_6cbb = { 3b c9 [2] 09 eb [2] 0f de [2] 21 de [2] 1e c2 }

  condition:
    any of them
}