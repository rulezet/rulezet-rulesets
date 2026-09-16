rule TTP_XOR_WriteProcessMemory_642d {
  strings:
    $key_642d = { 33 5f [2] 01 7d [2] 07 48 [2] 29 48 [2] 16 54 }

  condition:
    any of them
}