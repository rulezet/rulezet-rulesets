rule TTP_XOR_WriteProcessMemory_553b {
  strings:
    $key_553b = { 02 49 [2] 30 6b [2] 36 5e [2] 18 5e [2] 27 42 }

  condition:
    any of them
}