rule TTP_XOR_WriteProcessMemory_523b {
  strings:
    $key_523b = { 05 49 [2] 37 6b [2] 31 5e [2] 1f 5e [2] 20 42 }

  condition:
    any of them
}