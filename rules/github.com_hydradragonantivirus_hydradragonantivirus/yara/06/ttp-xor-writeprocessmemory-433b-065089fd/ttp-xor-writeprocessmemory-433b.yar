rule TTP_XOR_WriteProcessMemory_433b {
  strings:
    $key_433b = { 14 49 [2] 26 6b [2] 20 5e [2] 0e 5e [2] 31 42 }

  condition:
    any of them
}