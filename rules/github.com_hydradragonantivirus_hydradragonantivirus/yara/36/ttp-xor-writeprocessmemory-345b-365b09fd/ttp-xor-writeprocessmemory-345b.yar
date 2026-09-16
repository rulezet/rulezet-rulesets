rule TTP_XOR_WriteProcessMemory_345b {
  strings:
    $key_345b = { 63 29 [2] 51 0b [2] 57 3e [2] 79 3e [2] 46 22 }

  condition:
    any of them
}