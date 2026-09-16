rule TTP_XOR_WriteProcessMemory_cdbb {
  strings:
    $key_cdbb = { 9a c9 [2] a8 eb [2] ae de [2] 80 de [2] bf c2 }

  condition:
    any of them
}