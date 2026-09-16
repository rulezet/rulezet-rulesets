rule TTP_XOR_WriteProcessMemory_043b {
  strings:
    $key_043b = { 53 49 [2] 61 6b [2] 67 5e [2] 49 5e [2] 76 42 }

  condition:
    any of them
}