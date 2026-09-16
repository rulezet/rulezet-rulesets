rule TTP_XOR_WriteProcessMemory_1cbb {
  strings:
    $key_1cbb = { 4b c9 [2] 79 eb [2] 7f de [2] 51 de [2] 6e c2 }

  condition:
    any of them
}