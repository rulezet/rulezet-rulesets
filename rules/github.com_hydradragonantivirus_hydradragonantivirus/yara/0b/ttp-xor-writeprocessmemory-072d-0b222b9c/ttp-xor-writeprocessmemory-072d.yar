rule TTP_XOR_WriteProcessMemory_072d {
  strings:
    $key_072d = { 50 5f [2] 62 7d [2] 64 48 [2] 4a 48 [2] 75 54 }

  condition:
    any of them
}