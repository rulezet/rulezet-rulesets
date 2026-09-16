rule TTP_XOR_WriteProcessMemory_063b {
  strings:
    $key_063b = { 51 49 [2] 63 6b [2] 65 5e [2] 4b 5e [2] 74 42 }

  condition:
    any of them
}