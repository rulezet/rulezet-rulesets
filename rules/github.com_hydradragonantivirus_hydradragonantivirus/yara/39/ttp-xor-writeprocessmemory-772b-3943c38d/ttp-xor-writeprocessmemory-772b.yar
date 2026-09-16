rule TTP_XOR_WriteProcessMemory_772b {
  strings:
    $key_772b = { 20 59 [2] 12 7b [2] 14 4e [2] 3a 4e [2] 05 52 }

  condition:
    any of them
}