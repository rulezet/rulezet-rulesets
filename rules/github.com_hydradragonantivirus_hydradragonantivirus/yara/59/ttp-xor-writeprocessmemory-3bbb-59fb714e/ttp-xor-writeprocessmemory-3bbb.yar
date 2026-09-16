rule TTP_XOR_WriteProcessMemory_3bbb {
  strings:
    $key_3bbb = { 6c c9 [2] 5e eb [2] 58 de [2] 76 de [2] 49 c2 }

  condition:
    any of them
}