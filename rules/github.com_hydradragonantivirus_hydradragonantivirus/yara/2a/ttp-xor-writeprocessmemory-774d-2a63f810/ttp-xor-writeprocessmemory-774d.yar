rule TTP_XOR_WriteProcessMemory_774d {
  strings:
    $key_774d = { 20 3f [2] 12 1d [2] 14 28 [2] 3a 28 [2] 05 34 }

  condition:
    any of them
}