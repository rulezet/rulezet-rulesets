rule TTP_XOR_WriteProcessMemory_066b {
  strings:
    $key_066b = { 51 19 [2] 63 3b [2] 65 0e [2] 4b 0e [2] 74 12 }

  condition:
    any of them
}