rule TTP_XOR_WriteProcessMemory_363b {
  strings:
    $key_363b = { 61 49 [2] 53 6b [2] 55 5e [2] 7b 5e [2] 44 42 }

  condition:
    any of them
}