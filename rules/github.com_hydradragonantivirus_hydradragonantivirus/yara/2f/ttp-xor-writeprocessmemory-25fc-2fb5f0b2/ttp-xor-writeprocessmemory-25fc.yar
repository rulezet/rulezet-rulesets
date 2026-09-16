rule TTP_XOR_WriteProcessMemory_25fc {
  strings:
    $key_25fc = { 72 8e [2] 40 ac [2] 46 99 [2] 68 99 [2] 57 85 }

  condition:
    any of them
}