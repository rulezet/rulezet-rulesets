rule TTP_XOR_WriteProcessMemory_313b {
  strings:
    $key_313b = { 66 49 [2] 54 6b [2] 52 5e [2] 7c 5e [2] 43 42 }

  condition:
    any of them
}