rule TTP_XOR_WriteProcessMemory_6bbb {
  strings:
    $key_6bbb = { 3c c9 [2] 0e eb [2] 08 de [2] 26 de [2] 19 c2 }

  condition:
    any of them
}