rule TTP_XOR_WriteProcessMemory_257c {
  strings:
    $key_257c = { 72 0e [2] 40 2c [2] 46 19 [2] 68 19 [2] 57 05 }

  condition:
    any of them
}