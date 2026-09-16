rule TTP_XOR_WriteProcessMemory_263b {
  strings:
    $key_263b = { 71 49 [2] 43 6b [2] 45 5e [2] 6b 5e [2] 54 42 }

  condition:
    any of them
}