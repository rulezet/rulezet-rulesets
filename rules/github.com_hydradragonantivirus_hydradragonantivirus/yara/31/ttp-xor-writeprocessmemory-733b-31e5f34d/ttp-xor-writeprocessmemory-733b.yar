rule TTP_XOR_WriteProcessMemory_733b {
  strings:
    $key_733b = { 24 49 [2] 16 6b [2] 10 5e [2] 3e 5e [2] 01 42 }

  condition:
    any of them
}