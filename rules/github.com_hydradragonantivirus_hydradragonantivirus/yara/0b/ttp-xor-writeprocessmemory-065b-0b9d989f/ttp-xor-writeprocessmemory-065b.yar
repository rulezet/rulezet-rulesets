rule TTP_XOR_WriteProcessMemory_065b {
  strings:
    $key_065b = { 51 29 [2] 63 0b [2] 65 3e [2] 4b 3e [2] 74 22 }

  condition:
    any of them
}