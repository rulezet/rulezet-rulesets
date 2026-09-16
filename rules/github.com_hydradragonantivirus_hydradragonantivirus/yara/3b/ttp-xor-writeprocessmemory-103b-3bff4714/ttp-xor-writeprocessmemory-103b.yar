rule TTP_XOR_WriteProcessMemory_103b {
  strings:
    $key_103b = { 47 49 [2] 75 6b [2] 73 5e [2] 5d 5e [2] 62 42 }

  condition:
    any of them
}