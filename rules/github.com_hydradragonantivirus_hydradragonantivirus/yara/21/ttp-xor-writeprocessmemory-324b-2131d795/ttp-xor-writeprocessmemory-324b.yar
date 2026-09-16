rule TTP_XOR_WriteProcessMemory_324b {
  strings:
    $key_324b = { 65 39 [2] 57 1b [2] 51 2e [2] 7f 2e [2] 40 32 }

  condition:
    any of them
}