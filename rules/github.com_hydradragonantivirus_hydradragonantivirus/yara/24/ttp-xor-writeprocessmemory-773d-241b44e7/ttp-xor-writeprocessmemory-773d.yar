rule TTP_XOR_WriteProcessMemory_773d {
  strings:
    $key_773d = { 20 4f [2] 12 6d [2] 14 58 [2] 3a 58 [2] 05 44 }

  condition:
    any of them
}