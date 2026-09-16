rule TTP_XOR_WriteProcessMemory_721d {
  strings:
    $key_721d = { 25 6f [2] 17 4d [2] 11 78 [2] 3f 78 [2] 00 64 }

  condition:
    any of them
}