rule TTP_XOR_WriteProcessMemory_342b {
  strings:
    $key_342b = { 63 59 [2] 51 7b [2] 57 4e [2] 79 4e [2] 46 52 }

  condition:
    any of them
}