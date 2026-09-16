rule TTP_XOR_WriteProcessMemory_352d {
  strings:
    $key_352d = { 62 5f [2] 50 7d [2] 56 48 [2] 78 48 [2] 47 54 }

  condition:
    any of them
}