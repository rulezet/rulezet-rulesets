rule TTP_XOR_WriteProcessMemory_663b {
  strings:
    $key_663b = { 31 49 [2] 03 6b [2] 05 5e [2] 2b 5e [2] 14 42 }

  condition:
    any of them
}