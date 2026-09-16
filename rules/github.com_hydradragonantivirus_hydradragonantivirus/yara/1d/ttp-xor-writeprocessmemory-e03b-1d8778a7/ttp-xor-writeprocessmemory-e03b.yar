rule TTP_XOR_WriteProcessMemory_e03b {
  strings:
    $key_e03b = { b7 49 [2] 85 6b [2] 83 5e [2] ad 5e [2] 92 42 }

  condition:
    any of them
}