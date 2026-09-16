rule TTP_XOR_WriteProcessMemory_002d {
  strings:
    $key_002d = { 57 5f [2] 65 7d [2] 63 48 [2] 4d 48 [2] 72 54 }

  condition:
    any of them
}