rule TTP_XOR_WriteProcessMemory_7728 {
  strings:
    $key_7728 = { 20 5a [2] 12 78 [2] 14 4d [2] 3a 4d [2] 05 51 }

  condition:
    any of them
}